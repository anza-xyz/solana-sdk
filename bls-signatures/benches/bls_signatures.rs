use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bls_signatures::{
        keypair::Keypair,
        pubkey::{PubkeyProjective, VerifiablePubkey},
        signature::SignatureProjective,
    },
    std::hint::black_box,
};
#[cfg(feature = "parallel")]
use {
    solana_bls_signatures::{
        pubkey::Pubkey,
        signature::{Signature, VerificationOptions},
    },
    std::collections::HashSet,
};

// Benchmark for verifying a single signature
fn bench_single_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_signature");
    let keypair = Keypair::new();
    let message = b"test message";

    group.bench_function("signature_generation", |b| {
        b.iter(|| black_box(keypair.sign(message)));
    });

    let signature = keypair.sign(message);
    group.bench_function("verify_signature", |b| {
        b.iter(|| black_box(keypair.public.verify_signature(&signature, message)).unwrap());
    });
    group.finish();
}

// Worst-case benchmark for aggregate signature verification
fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_verify");
    // Test with a range of validator counts to simulate different scales
    for num_validators in [64, 128, 256, 512, 1024, 2048].iter() {
        let message = b"test message";
        let keypairs: Vec<Keypair> = (0..*num_validators).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<PubkeyProjective> = keypairs
            .iter()
            .map(|kp| PubkeyProjective::try_from(&kp.public).unwrap())
            .collect();
        let signatures: Vec<SignatureProjective> =
            keypairs.iter().map(|kp| kp.sign(message)).collect();

        let pubkey_refs: Vec<&PubkeyProjective> = pubkeys.iter().collect();
        let signature_refs: Vec<&SignatureProjective> = signatures.iter().collect();

        // Benchmark for aggregating multiple signatures
        group.bench_function(format!("{num_validators} signature aggregation"), |b| {
            b.iter(|| black_box(SignatureProjective::aggregate(&signature_refs)));
        });

        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel signature aggregation"),
            |b| {
                b.iter(|| black_box(SignatureProjective::par_aggregate(&signature_refs)));
            },
        );

        // Benchmark for aggregating multiple public keys
        group.bench_function(format!("{num_validators} pubkey aggregation"), |b| {
            b.iter(|| black_box(PubkeyProjective::aggregate(&pubkey_refs)));
        });

        // Benchmark for aggregate verify
        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel pubkey aggregation"),
            |b| {
                b.iter(|| black_box(PubkeyProjective::par_aggregate(&pubkey_refs)));
            },
        );

        group.bench_function(
            format!("{num_validators} sequential aggregate verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::aggregate_verify(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(verification_result);
                });
            },
        );

        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel aggregate verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::par_aggregate_verify(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(verification_result);
                });
            },
        );
    }
    group.finish();
}

// Benchmark for generating a new keypair
fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| b.iter(|| black_box(Keypair::new)));
}

// Benchmark for creating and verifying a proof of possession
fn bench_proof_of_possession(c: &mut Criterion) {
    let keypair = Keypair::new();
    let pop = keypair.proof_of_possession();

    c.bench_function("proof_of_possession_creation", |b| {
        b.iter(|| black_box(keypair.proof_of_possession()));
    });

    c.bench_function("proof_of_possession_verification", |b| {
        b.iter(|| {
            black_box(keypair.public.verify_proof_of_possession(&pop)).unwrap();
        })
    });
}

// Benchmark for batch verification functions
#[cfg(feature = "parallel")]
fn bench_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify");
    let options = VerificationOptions {
        aggregation_threshold: std::num::NonZero::new(32).unwrap(),
    };

    for num_validators in [64, 128, 256, 512, 1024, 2048].iter() {
        let message = b"test_message";
        let keypairs: Vec<Keypair> = (0..*num_validators).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<Pubkey> = keypairs.iter().map(|kp| kp.public).collect();
        let pubkey_refs: Vec<&Pubkey> = pubkeys.iter().collect();

        // All signatures are valid
        let signatures: Vec<Signature> =
            keypairs.iter().map(|kp| kp.sign(message).into()).collect();
        let signature_refs: Vec<&Signature> = signatures.iter().collect();

        group.bench_function(
            format!("{num_validators} par_verify_batch (all valid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(results.iter().all(|&v| v));
                });
            },
        );

        group.bench_function(
            format!("{num_validators} par_verify_batch_binary_search (all valid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch_binary_search(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                            &options,
                        )
                        .unwrap(),
                    );
                    assert!(results.iter().all(|&v| v));
                });
            },
        );

        // --- Scenario 2: One signature is invalid ---
        let mut bad_signatures_one = signatures.clone();
        let invalid_sig_idx = num_validators / 2;
        bad_signatures_one[invalid_sig_idx] =
            keypairs[invalid_sig_idx].sign(b"wrong message").into();
        let bad_signature_refs_one: Vec<&Signature> = bad_signatures_one.iter().collect();

        group.bench_function(
            format!("{num_validators} par_verify_batch (one invalid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch(
                            &pubkey_refs,
                            &bad_signature_refs_one,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(!results[invalid_sig_idx]);
                });
            },
        );

        group.bench_function(
            format!("{num_validators} par_verify_batch_binary_search (one invalid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch_binary_search(
                            &pubkey_refs,
                            &bad_signature_refs_one,
                            message,
                            &options,
                        )
                        .unwrap(),
                    );
                    assert!(!results[invalid_sig_idx]);
                });
            },
        );

        // --- Scenario 3: 10% of signatures are invalid ---
        let mut bad_signatures_10_percent = signatures.clone();
        let num_invalid = num_validators / 10;
        let mut invalid_indices = HashSet::new();
        for i in 0..num_invalid {
            let idx = i * 10;
            bad_signatures_10_percent[idx] = keypairs[idx].sign(b"wrong message").into();
            invalid_indices.insert(idx);
        }
        let bad_signature_refs_10_percent: Vec<&Signature> =
            bad_signatures_10_percent.iter().collect();

        group.bench_function(
            format!("{num_validators} par_verify_batch (10% invalid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch(
                            &pubkey_refs,
                            &bad_signature_refs_10_percent,
                            message,
                        )
                        .unwrap(),
                    );
                    for (i, &is_valid) in results.iter().enumerate() {
                        if invalid_indices.contains(&i) {
                            assert!(!is_valid);
                        } else {
                            assert!(is_valid);
                        }
                    }
                });
            },
        );

        group.bench_function(
            format!("{num_validators} par_verify_batch_binary_search (10% invalid)"),
            |b| {
                b.iter(|| {
                    let results = black_box(
                        SignatureProjective::par_verify_batch_binary_search(
                            &pubkey_refs,
                            &bad_signature_refs_10_percent,
                            message,
                            &options,
                        )
                        .unwrap(),
                    );
                    for (i, &is_valid) in results.iter().enumerate() {
                        if invalid_indices.contains(&i) {
                            assert!(!is_valid);
                        } else {
                            assert!(is_valid);
                        }
                    }
                });
            },
        );
    }
    group.finish()
}

// Stub function for when the `parallel` function is not enabled.
#[cfg(not(feature = "parallel"))]
fn bench_batch_verification(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_single_signature,
    bench_aggregate,
    bench_key_generation,
    bench_proof_of_possession,
    bench_batch_verification
);
criterion_main!(benches);
