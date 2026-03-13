# solana-bls-signatures

This crate provides an implementation of BLS (Boneh-Lynn-Shacham) signatures over the BLS12-381 elliptic curve.

It is primarily intended for use in the Solana Alpenglow consensus protocol, but it is general enough to be used in any Rust application requiring BLS signatures, threshold cryptography, or batch verification. Under the hood, it uses the `blst` library as its cryptographic backend.

---

## Features

- **Multiple Point Representations:** Convert seamlessly between serialized Bytes (`Signature`), Compressed Bytes (`SignatureCompressed`), Projective points (`SignatureProjective` optimized for fast aggregation), and Affine points (`SignatureAffine` optimized for pairings). The same representations exist for Public Keys and Proofs of Possession.
- **Ergonomic Verification:** Verify signatures bi-directionally (from the public key or the signature) using any representation type via the `VerifySignature` and `VerifiableSignature` traits.
- **Aggregate & Batch Verification:** Optimized multi-miller loop algorithms for verifying aggregated signatures against shared messages (multisig) or multiple distinct messages (batch verification).
- **Parallelization:** Optional `rayon` integration to speed up multi-scalar multiplications (MSMs) and heavy verification loops.
- **Rogue-Key Attack Prevention:** Type-safe wrappers like `PopVerified` ensure that aggregation only occurs with keys that have proven their Proof of Possession.

---

## Basic Usage Examples

### 1. Basic Usage

Generating a keypair, signing a message, and verifying the signature is straightforward:

```rust
use solana_bls_signatures::keypair::Keypair;

// 1. Generate a new random BLS keypair
let keypair = Keypair::new();
let message = b"hello, alpenglow!";

// 2. Sign the message
let signature = keypair.sign(message);

// 3. Verify the signature
// You can verify it directly against the keypair...
assert!(keypair.verify(&signature, message).is_ok());

// ...or you can verify it directly against the public key
assert!(keypair.public.verify_signature(&signature, message).is_ok());
```

### 2. Ergonomics & Type Flexibility

To optimize for different use cases, this crate provides four representations for signatures (and similarly for public keys and proofs of possession):

- `SignatureCompressed` (96-byte array)
- `Signature` (192-byte uncompressed array)
- `SignatureAffine` (Curve point optimized for pairing/verification)
- `SignatureProjective` (Curve point optimized for addition/aggregation)

You can cross-verify any signature type against any public key type. You can also call the verification method from either the public key or the signature itself:

```rust
use solana_bls_signatures::{
    keypair::Keypair,
    pubkey::VerifySignature,
    signature::{Signature, SignatureCompressed, SignatureAffine, SignatureProjective, VerifiableSignature},
};

let keypair = Keypair::new();
let message = b"ergonomics test";

// The default `.sign()` returns a SignatureProjective
let sig_projective: SignatureProjective = keypair.sign(message);

// Easily convert into other representations
let sig_affine: SignatureAffine = sig_projective.into();
let sig_compressed: SignatureCompressed = sig_projective.into(); // 96 bytes
let sig_uncompressed: Signature = sig_projective.into();         // 192 bytes

// Approach A: Verify via the Public Key
// You can pass projective, affine, or byte-level signatures
keypair.public.verify_signature(&sig_projective, message).unwrap();
keypair.public.verify_signature(&sig_affine, message).unwrap();
keypair.public.verify_signature(&sig_compressed, message).unwrap();
keypair.public.verify_signature(&sig_uncompressed, message).unwrap();

// Approach B: Verify via the Signature
// Import `VerifiableSignature` and call `.verify()` on the signature itself
sig_projective.verify(&keypair.public, message).unwrap();
sig_affine.verify(&keypair.public, message).unwrap();
sig_compressed.verify(&keypair.public, message).unwrap();
sig_uncompressed.verify(&keypair.public, message).unwrap();
```

### 3. Aggregate Signatures (Multisig)

BLS signatures allow multiple signers to sign a single message, and their signatures can be aggregated into one single, constant-size signature and public key.

```rust
use solana_bls_signatures::{
    keypair::Keypair,
    pubkey::{PubkeyProjective, VerifySignature},
    signature::SignatureProjective,
};

let message = b"shared consensus data";
let kp1 = Keypair::new();
let kp2 = Keypair::new();

let sig1 = kp1.sign(message);
let sig2 = kp2.sign(message);

// Aggregate the signatures and public keys
// (Requires an iterator over the references)
let agg_sig = SignatureProjective::aggregate([&sig1, &sig2].into_iter()).unwrap();
let agg_pub = PubkeyProjective::aggregate([&kp1.public, &kp2.public].into_iter()).unwrap();

// Verify the aggregated signature using the aggregated public key
agg_pub.verify_signature(&agg_sig, message).expect("Aggregated signature is valid");
```

### 4. Security: Rogue-Key Attacks & Proof of Possession

A well-known vulnerability in BLS signature aggregation is the Rogue Key Attack. If an attacker observes your public key, they can craft a malicious public key and signature that effectively "cancels out" your key, allowing them to forge an aggregated signature on behalf of the group.

One mitigation is to require a Proof of Possession (PoP) from every participant. A PoP is a cryptographic proof that the creator of a public key actually controls the corresponding private key.

To prevent accidental vulnerabilities and the aggregation of unverified keys, the aggregation and verification APIs strictly require the `PopVerified<T>` wrapper type. You cannot mathematically aggregate public keys in this crate without first proving you've verified their PoP.

```rust
use solana_bls_signatures::{
    keypair::Keypair,
    pubkey::{Pubkey, VerifyPop, VerifySignature}
};

// 1. Generate a random BLS keypair and sign a message
let keypair = Keypair::new();
let message = b"rogue-key protection";
let signature = keypair.sign(message);

// 2. Generate a Proof of Possession to share with the network
let pop = keypair.proof_of_possession(None);

// Assume we receive the raw public key bytes, signature, and PoP over the network
let raw_pubkey: Pubkey = (*keypair.public).into();

// ❌ THIS WILL FAIL TO COMPILE!
// The type system prevents using unverified keys for signature verification.
// raw_pubkey.verify_signature(&signature, message).unwrap();

// 3. Verify the PoP. Upon success, it returns a `PopVerified` wrapper,
// making it type-safe and eligible for signature verification/aggregation.
let verified_pubkey = raw_pubkey.verify_and_wrap_pop(&pop, None)
    .expect("Proof of Possession is valid!");

// ✅ THIS WILL COMPILE!
// The `PopVerified` wrapper implements `VerifySignature`.
verified_pubkey.verify_signature(&signature, message).unwrap();
```

---

## `no_std` Support

While you will see `#![no_std]` markers and `alloc` usage throughout the codebase, true `no_std` support is currently a work in progress. Certain dependencies, cryptographic backend fallbacks, and optional features (like `rayon`) currently rely on the standard library. The `no_std` markers exist to pave the way for full embedded/on-chain support in a future release.
