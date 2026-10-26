//! Opt-in shadow verification for evaluating SIMD-0376 on live traffic.
//!
//! With the `triple-verify` feature enabled and an observer registered
//! through [`set_observer`], every [`Signature::verify`] call runs three
//! verifiers, times each, and passes a [`TripleVerifyEvent`] to the observer:
//!
//! * [`Verifier::Dalek`]: solana-ed25519's `verify_dalek`. Its result is
//!   returned, as without this feature.
//! * [`Verifier::Simd0376`]: solana-ed25519's `verify_simd0376`.
//! * [`Verifier::Ed25519Dalek`]: the ed25519-dalek crate's `verify_strict`,
//!   the implementation `verify_dalek` is meant to match.
//!
//! Without an observer, `verify` runs `verify_dalek` alone.
//!
//! This module does no I/O: the observer decides what to record. It runs on
//! the verifying thread, so it should be cheap.

pub use solana_ed25519::ed_sigs::Error as VerifyError;
use {
    crate::Signature,
    core::cell::Cell,
    solana_ed25519::ed_sigs::{Signature as EdSignature, VerificationKey},
    std::{sync::OnceLock, time::Instant},
};

/// One of the three verifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifier {
    Dalek,
    Simd0376,
    Ed25519Dalek,
}

impl Verifier {
    /// One-letter code: `D`, `S` or `E`.
    pub fn code(self) -> u8 {
        match self {
            Self::Dalek => b'D',
            Self::Simd0376 => b'S',
            Self::Ed25519Dalek => b'E',
        }
    }
}

/// Run orders, rotated per call on each thread so that each verifier runs
/// first, second and third equally often and cache warm-up favours none.
const ORDERS: [[Verifier; 3]; 3] = {
    use Verifier::*;
    [
        [Dalek, Simd0376, Ed25519Dalek],
        [Simd0376, Ed25519Dalek, Dalek],
        [Ed25519Dalek, Dalek, Simd0376],
    ]
};

/// Results and timings of all three verifiers for one signature.
#[derive(Debug)]
pub struct TripleVerifyEvent<'a> {
    pub pubkey: &'a [u8],
    pub signature: &'a Signature,
    pub message: &'a [u8],
    /// The order the verifiers ran in.
    pub order: [Verifier; 3],
    /// solana-ed25519 public-key decompression, shared by `dalek` and
    /// `simd0376` and not included in either time.
    pub decompress_ns: u32,
    /// ed25519-dalek public-key decompression, not included in
    /// `ed25519_dalek_ns`.
    pub ed25519_dalek_decompress_ns: u32,
    pub dalek: Result<(), VerifyError>,
    pub dalek_ns: u32,
    pub simd0376: Result<(), VerifyError>,
    pub simd0376_ns: u32,
    /// Key-parse failures map to `MalformedPublicKey`, verification failures
    /// to `InvalidSignature`.
    pub ed25519_dalek: Result<(), VerifyError>,
    pub ed25519_dalek_ns: u32,
}

/// Receives one [`TripleVerifyEvent`] per verified signature.
pub type Observer = fn(&TripleVerifyEvent<'_>);

static OBSERVER: OnceLock<Observer> = OnceLock::new();

std::thread_local! {
    static CALLS: Cell<u64> = const { Cell::new(0) };
}

/// Registers the process-wide observer. Can be set once; returns the given
/// observer back if one is already registered.
pub fn set_observer(observer: Observer) -> Result<(), Observer> {
    OBSERVER.set(observer)
}

fn elapsed_ns(start: Instant) -> u32 {
    u32::try_from(start.elapsed().as_nanos()).unwrap_or(u32::MAX)
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, u32) {
    let start = Instant::now();
    let result = f();
    (result, elapsed_ns(start))
}

/// Returns the `verify_dalek` result. With an observer registered, also runs
/// `verify_simd0376` and ed25519-dalek's `verify_strict` and reports all
/// three.
pub(crate) fn verify(
    signature: &Signature,
    pubkey_bytes: &[u8],
    message_bytes: &[u8],
) -> Result<(), VerifyError> {
    let ed_sig = EdSignature::from(*signature.as_array());
    let Some(observer) = OBSERVER.get() else {
        return VerificationKey::try_from(pubkey_bytes)?.verify_dalek(&ed_sig, message_bytes);
    };

    let (publickey, decompress_ns) = timed(|| VerificationKey::try_from(pubkey_bytes));
    let (dalek_key, ed25519_dalek_decompress_ns) = timed(|| {
        let bytes: &[u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| VerifyError::MalformedPublicKey)?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| VerifyError::MalformedPublicKey)
    });
    let dalek_sig = ed25519_dalek::Signature::from_bytes(signature.as_array());

    let rotation = CALLS.with(|calls| {
        let n = calls.get();
        calls.set(n.wrapping_add(1));
        (n % 3) as usize
    });
    let order = ORDERS[rotation];

    let (mut dalek, mut simd0376, mut ed25519_dalek) = (Ok(()), Ok(()), Ok(()));
    let (mut dalek_ns, mut simd0376_ns, mut ed25519_dalek_ns) = (0, 0, 0);
    for verifier in order {
        match verifier {
            Verifier::Dalek => {
                (dalek, dalek_ns) = match &publickey {
                    Ok(vk) => timed(|| vk.verify_dalek(&ed_sig, message_bytes)),
                    Err(err) => (Err(*err), 0),
                };
            }
            Verifier::Simd0376 => {
                (simd0376, simd0376_ns) = match &publickey {
                    Ok(vk) => timed(|| vk.verify_simd0376(&ed_sig, message_bytes)),
                    Err(err) => (Err(*err), 0),
                };
            }
            Verifier::Ed25519Dalek => {
                (ed25519_dalek, ed25519_dalek_ns) = match &dalek_key {
                    Ok(key) => timed(|| {
                        key.verify_strict(message_bytes, &dalek_sig)
                            .map_err(|_| VerifyError::InvalidSignature)
                    }),
                    Err(err) => (Err(*err), 0),
                };
            }
        }
    }

    observer(&TripleVerifyEvent {
        pubkey: pubkey_bytes,
        signature,
        message: message_bytes,
        order,
        decompress_ns,
        ed25519_dalek_decompress_ns,
        dalek,
        dalek_ns,
        simd0376,
        simd0376_ns,
        ed25519_dalek,
        ed25519_dalek_ns,
    });
    dalek
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{sync::Mutex, vec::Vec},
    };

    /// Accepted by `verify_simd0376` (cofactored) but rejected by
    /// `verify_dalek` and ed25519-dalek's `verify_strict` (cofactorless): a
    /// valid signature with an order-8 point added to `R`. Generated by
    /// ed25519-triple-verify in anza-xyz/cryptography.
    const TORSION_PUBKEY: &str = "c8f4cfd7ec9c81e16c77144a4d1ce0dca0339661df313cceb9203113468fb608";
    const TORSION_SIG: &str = "9e556c89c2f8fdce92210fa586de4cf4cf17eacf4bb3060ca88c0011e90979c7\
                               d27eaa759f0bdf95f46276422e6d45a90f46c4fe307cd54bf7f926016bce630b";
    const TORSION_MSG: &[u8] = b"dual verify";

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    type Seen = ((bool, bool, bool), Verifier);
    static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

    fn record(event: &TripleVerifyEvent<'_>) {
        // The observer is process-wide: ignore other tests' verifications.
        if event.message != TORSION_MSG {
            return;
        }
        SEEN.lock().unwrap().push((
            (
                event.dalek.is_ok(),
                event.simd0376.is_ok(),
                event.ed25519_dalek.is_ok(),
            ),
            event.order[0],
        ));
    }

    #[test]
    fn test_observer_sees_all_results_and_dalek_decides() {
        let pubkey = unhex(TORSION_PUBKEY);
        let signature = Signature::try_from(unhex(TORSION_SIG).as_slice()).unwrap();

        // No observer yet: dalek alone.
        assert!(!signature.verify(&pubkey, TORSION_MSG));
        assert!(SEEN.lock().unwrap().is_empty());

        assert!(set_observer(record).is_ok());
        assert!(set_observer(record).is_err());

        // Three calls: dalek rejects each time, so verify rejects, while the
        // observer sees simd0376 accept. The run order rotates.
        for _ in 0..3 {
            assert!(!signature.verify(&pubkey, TORSION_MSG));
        }
        // Malformed public key: all rejected, still reported.
        assert!(!signature.verify(&[2u8; 32], TORSION_MSG));

        let seen = SEEN.lock().unwrap();
        assert_eq!(seen.len(), 4);
        for (results, _) in &seen[..3] {
            assert_eq!(*results, (false, true, false));
        }
        let mut firsts: Vec<u8> = seen[..3].iter().map(|(_, first)| first.code()).collect();
        firsts.sort_unstable();
        assert_eq!(firsts, b"DES");
        assert_eq!(seen[3].0, (false, false, false));
    }
}
