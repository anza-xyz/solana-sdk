//! Allocation-counting regression tests for the signature verification hot paths.
//!
//! This lives in its own integration-test binary so that the `#[global_allocator]`
//! below is scoped to it and does not affect the unit tests or the other
//! integration tests.
//!
//! Counters are thread-local, so `cargo test`'s parallel test threads cannot
//! pollute each other's measurements. The flip side is that allocations made on
//! other threads (e.g. rayon workers under the `parallel` feature) are not
//! counted; the `verify_distinct` rows below only assert on the sequential path.
//!
//! The assertions are exact on purpose: a change that adds or removes an
//! allocation should fail loudly, not disappear inside a tolerance. If you
//! change allocation behaviour intentionally, update the numbers and the
//! breakdown comment next to them.
//!
//! Run with:
//!
//! ```text
//! cargo test -p solana-bls-signatures --release --test alloc_counting -- --nocapture --test-threads=1
//! ```

use {
    solana_bls_signatures::{
        hash::{HashedMessage, PreparedHashedMessage},
        keypair::Keypair,
        proof_of_possession::ProofOfPossessionAffine,
        pubkey::{PopVerified, PubkeyAffine, VerifyPop, VerifySignature},
        signature::{SignatureAffine, SignatureProjective},
    },
    std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
        hint::black_box,
        thread::LocalKey,
    },
};

// Counting allocator

thread_local! {
    // `const` initialisers with a `Copy` payload compile to a plain
    // `#[thread_local]` static on native-TLS targets (every tier-1 target): no
    // lazy initialisation and no destructor registration, so touching these
    // from inside the allocator cannot itself allocate or recurse.
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static REALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

#[inline]
fn bump(counter: &'static LocalKey<Cell<usize>>, by: usize) {
    // `try_with` rather than `with`: never panic inside the allocator, even if a
    // platform reports the key as unavailable during thread teardown.
    let _ = counter.try_with(|c| c.set(c.get().saturating_add(by)));
}

struct CountingAllocator;

// SAFETY: every method forwards to `System` with the same arguments and returns
// its result unchanged, so the `GlobalAlloc` contract is upheld by `System`.
// The only extra work is updating thread-local `Cell<usize>` counters, which
// neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(&ALLOCS, 1);
        bump(&BYTES, layout.size());
        // SAFETY: same preconditions as ours, forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(&ALLOCS, 1);
        bump(&BYTES, layout.size());
        // SAFETY: same preconditions as ours, forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Counted separately from `allocs` so that `Vec` growth is visible as
        // its own signal. Bytes are the requested new size, which is also how
        // DHAT accounts for a realloc.
        bump(&REALLOCS, 1);
        bump(&BYTES, new_size);
        // SAFETY: same preconditions as ours, forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same preconditions as ours, forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

// Measurement helpers

/// Allocation events recorded on the current thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocStats {
    /// Calls to `alloc` + `alloc_zeroed`.
    allocs: usize,
    /// Calls to `realloc`.
    reallocs: usize,
    /// Bytes requested across allocs and reallocs.
    bytes: usize,
}

fn reset_counters() {
    ALLOCS.with(|c| c.set(0));
    REALLOCS.with(|c| c.set(0));
    BYTES.with(|c| c.set(0));
}

fn snapshot() -> AllocStats {
    AllocStats {
        allocs: ALLOCS.with(Cell::get),
        reallocs: REALLOCS.with(Cell::get),
        bytes: BYTES.with(Cell::get),
    }
}

/// Runs `f` once unmeasured (warm-up, to exclude one-time initialisation such
/// as `LazyLock` statics), then once measured, and prints one line.
///
/// Everything printed happens after the snapshot, outside the measured window.
fn measure<R>(label: &str, mut f: impl FnMut() -> R) -> AllocStats {
    black_box(f());
    reset_counters();
    let out = f();
    let stats = snapshot();
    black_box(out);
    println!(
        "{label:<52} allocs={:>4}  reallocs={:>3}  bytes={:>8}",
        stats.allocs, stats.reallocs, stats.bytes
    );
    stats
}

/// Asserts an exact allocation profile with no reallocs.
#[track_caller]
fn assert_stats(actual: AllocStats, allocs: usize, bytes: usize) {
    let expected = AllocStats {
        allocs,
        reallocs: 0,
        bytes,
    };
    assert_eq!(actual, expected, "allocation profile changed");
}

/// Like `assert_stats`, but only on the sequential path. Under `parallel` the
/// grouping sort goes through rayon and that profile has not been measured, so
/// the row is printed but not asserted.
#[track_caller]
fn assert_sequential_stats(actual: AllocStats, allocs: usize, bytes: usize) {
    #[cfg(not(feature = "parallel"))]
    assert_stats(actual, allocs, bytes);
    #[cfg(feature = "parallel")]
    let _ = (actual, allocs, bytes);
}

// Fixtures

const MESSAGE: &[u8] = b"solana-bls-signatures allocation harness";

/// Size of one `blstrs::G2Prepared` line table: 68 × `blst_fp6` (288 bytes).
const G2_PREPARED_BYTES: usize = 19_584;

/// One signer, one message. Everything the verify calls need is built here,
/// outside the measured window, and signatures/proofs are already affine so
/// `try_as_affine` is a plain copy inside the window.
struct SingleFixture {
    keypair: Keypair,
    signature: SignatureAffine,
    hashed: HashedMessage,
    prepared: PreparedHashedMessage,
    pop: ProofOfPossessionAffine,
}

impl SingleFixture {
    fn new() -> Self {
        let keypair = Keypair::new();
        let signature = SignatureAffine::from(keypair.sign(MESSAGE));
        let hashed = HashedMessage::new(MESSAGE);
        let prepared = PreparedHashedMessage::from_hashed_message(&hashed);
        let pop = ProofOfPossessionAffine::from(keypair.proof_of_possession(None));
        Self {
            keypair,
            signature,
            hashed,
            prepared,
            pop,
        }
    }
}

const DISTINCT_SIGNERS: usize = 100;
const DISTINCT_MESSAGES: usize = 5;

/// `DISTINCT_SIGNERS` signers spread evenly over `DISTINCT_MESSAGES` messages
/// (signer `i` signs message `i % DISTINCT_MESSAGES`), so the screening path
/// has to group and ends up with `DISTINCT_MESSAGES` pairing terms.
struct DistinctFixture {
    keypairs: Vec<Keypair>,
    signatures: Vec<SignatureAffine>,
    message_set: Vec<Vec<u8>>,
    prepared_set: Vec<PreparedHashedMessage>,
}

impl DistinctFixture {
    fn new() -> Self {
        let message_set: Vec<Vec<u8>> = (0..DISTINCT_MESSAGES)
            .map(|i| format!("distinct message {i}").into_bytes())
            .collect();
        let keypairs: Vec<Keypair> = (0..DISTINCT_SIGNERS).map(|_| Keypair::new()).collect();
        let signatures = keypairs
            .iter()
            .zip(message_set.iter().cycle())
            .map(|(keypair, message)| SignatureAffine::from(keypair.sign(message)))
            .collect();
        let prepared_set = message_set
            .iter()
            .map(|message| PreparedHashedMessage::new(message))
            .collect();
        Self {
            keypairs,
            signatures,
            message_set,
            prepared_set,
        }
    }

    fn pubkeys(&self) -> impl ExactSizeIterator<Item = &PopVerified<PubkeyAffine>> {
        self.keypairs.iter().map(|keypair| &keypair.public)
    }

    /// One `&[u8]` per signer. Built outside the measured window.
    fn messages(&self) -> Vec<&[u8]> {
        self.message_set
            .iter()
            .map(Vec::as_slice)
            .cycle()
            .take(DISTINCT_SIGNERS)
            .collect()
    }

    /// One `&PreparedHashedMessage` per signer. Built outside the measured window.
    fn prepared(&self) -> Vec<&PreparedHashedMessage> {
        self.prepared_set
            .iter()
            .cycle()
            .take(DISTINCT_SIGNERS)
            .collect()
    }
}

// Tests (numbered so `--test-threads=1` prints them in this order)

#[test]
fn alloc_01_verify_signature() {
    let fx = SingleFixture::new();
    let stats = measure("verify_signature", || {
        fx.keypair
            .public
            .verify_signature(&fx.signature, MESSAGE)
            .expect("valid signature")
    });
    // Two line tables: the hashed message (`from_hashed_message`) and the
    // signature (`_verify_signature_prepared`).
    assert_stats(stats, 2, 2 * G2_PREPARED_BYTES);
}

#[test]
fn alloc_02_verify_signature_pre_hashed() {
    let fx = SingleFixture::new();
    let stats = measure("verify_signature_pre_hashed", || {
        fx.keypair
            .public
            .verify_signature_pre_hashed(&fx.signature, &fx.hashed)
            .expect("valid signature")
    });
    // Same two line tables as `verify_signature`; hashing does not allocate.
    assert_stats(stats, 2, 2 * G2_PREPARED_BYTES);
}

#[test]
fn alloc_03_verify_signature_prepared() {
    let fx = SingleFixture::new();
    let stats = measure("verify_signature_prepared", || {
        fx.keypair
            .public
            .verify_signature_prepared(&fx.signature, &fx.prepared)
            .expect("valid signature")
    });
    // One line table, for the signature, even though the caller already
    // prepared the message.
    assert_stats(stats, 1, G2_PREPARED_BYTES);
}

#[test]
fn alloc_04_prepared_hashed_message_from_hashed_message() {
    let fx = SingleFixture::new();
    let stats = measure("PreparedHashedMessage::from_hashed_message", || {
        PreparedHashedMessage::from_hashed_message(&fx.hashed)
    });
    // The line table itself.
    assert_stats(stats, 1, G2_PREPARED_BYTES);
}

#[test]
fn alloc_05_verify_proof_of_possession() {
    let fx = SingleFixture::new();
    let stats = measure("verify_proof_of_possession", || {
        fx.keypair
            .public
            .verify_proof_of_possession(&fx.pop, None)
            .expect("valid proof of possession")
    });
    // Two line tables (hashed pubkey and proof) plus a 48-byte `Vec` for the
    // bound PoP payload (empty payload + compressed pubkey) in
    // `hash_bound_pop_to_projective`.
    assert_stats(stats, 3, 2 * G2_PREPARED_BYTES + 48);
}

#[test]
fn alloc_06_verify_distinct() {
    let fx = DistinctFixture::new();
    let messages = fx.messages();
    let stats = measure("verify_distinct (100 sigs, 5 messages)", || {
        SignatureProjective::verify_distinct(
            fx.pubkeys(),
            fx.signatures.iter(),
            messages.iter().copied(),
        )
        .expect("valid aggregate")
    });
    // Line tables: 5 grouped messages + 1 aggregate signature = 6 × 19 584.
    // Grouping/bookkeeping `Vec`s (8 allocs, 129 856 bytes):
    //   hashed_messages          100 × 192 = 19 200  (`verify_distinct`)
    //   pubkeys_affine           100 ×  96 =  9 600
    //   hashed_messages_owned    100 × 192 = 19 200
    //   entries                  100 × 480 = 48 000  (`group_hashed_terms`)
    //   grouped_pubkeys          100 × 144 = 14 400  (capacity 100, len 5)
    //   grouped_hashed_messages  100 × 192 = 19 200  (capacity 100, len 5)
    //   grouped_prepared_hashes    5 ×  32 =    160  (the `Vec<G2Prepared>` spine)
    //   terms                      6 ×  16 =     96
    // The projective→affine `collect()` in `group_hashed_terms` reuses its
    // buffer in place and does not allocate.
    assert_sequential_stats(stats, 14, 6 * G2_PREPARED_BYTES + 129_856);
}

#[test]
fn alloc_07_verify_distinct_prepared() {
    let fx = DistinctFixture::new();
    let prepared = fx.prepared();
    let stats = measure("verify_distinct_prepared (100 sigs, 5 messages)", || {
        SignatureProjective::verify_distinct_prepared(
            fx.pubkeys(),
            fx.signatures.iter(),
            prepared.iter().copied(),
        )
        .expect("valid aggregate")
    });
    // Line tables: 1 (the aggregate signature).
    // Grouping/bookkeeping `Vec`s (6 allocs, 55 296 bytes):
    //   pubkeys_affine           100 ×  96 =  9 600
    //   prepared_refs            100 ×   8 =    800
    //   entries                  100 × 296 = 29 600  (`group_prepared_terms`)
    //   grouped_pubkeys          100 × 144 = 14 400  (capacity 100, len 5)
    //   grouped_prepared         100 ×   8 =    800  (capacity 100, len 5)
    //   terms                      6 ×  16 =     96
    assert_sequential_stats(stats, 7, G2_PREPARED_BYTES + 55_296);
}
