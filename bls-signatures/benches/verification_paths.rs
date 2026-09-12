// Run with the verification_paths Cargo bench target (harness = false).
// Preparation benchmarks include destruction of the temporary preparation.
// Prepared verification reuses a preparation created outside the timed loop.

use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bls_signatures::{
        error::BlsError,
        hash::{HashedMessage, HashedPoPPayload, PreparedHashedMessage},
        keypair::Keypair,
        proof_of_possession::ProofOfPossessionAffine,
        pubkey::{VerifyPop, VerifySignature},
        signature::{SignatureAffine, SignatureCompressed, SignatureProjective},
    },
    std::{hint::black_box, time::Duration},
};

fn verification_paths(c: &mut Criterion) {
    proof_of_possession_paths(c);

    #[cfg(feature = "parallel")]
    parallel_aggregate_paths(c);

    // Use the same fixtures as the allocation regression test.
    let keypair = Keypair::derive(&[42u8; 32]).expect("derive fixture key");
    let message: &[u8] = b"solana-bls-signatures allocation baseline";
    let valid: SignatureCompressed = keypair.sign(message).into();
    let wrong: SignatureCompressed = keypair.sign(b"a different message").into();
    let hashed = HashedMessage::new(message);
    let prepared = PreparedHashedMessage::from_hashed_message(&hashed);

    let mut setup = c.benchmark_group("bls_setup");
    setup.bench_function("hash_message", |b| {
        b.iter(|| black_box(HashedMessage::new(black_box(message))));
    });
    setup.bench_function("prepare_from_hashed", |b| {
        b.iter(|| {
            drop(black_box(PreparedHashedMessage::from_hashed_message(
                black_box(&hashed),
            )));
        });
    });
    setup.bench_function("prepare_from_raw", |b| {
        b.iter(|| {
            drop(black_box(PreparedHashedMessage::new(black_box(message))));
        });
    });
    setup.finish();

    let mut verify = c.benchmark_group("bls_verify");
    for (status, encoded, expected) in [
        ("valid", &valid, Ok(())),
        ("wrong_message", &wrong, Err(BlsError::VerificationFailed)),
    ] {
        let affine = SignatureAffine::try_from(encoded).expect("decode fixture signature");

        // Validate all four paths before timing them. The wrong-message
        // signature is correctly encoded and belongs to the prime-order group.
        assert_eq!(
            keypair.public.verify_signature(&affine, message),
            expected,
            "raw/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature_pre_hashed(&affine, &hashed),
            expected,
            "pre_hashed/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature_prepared(&affine, &prepared),
            expected,
            "prepared/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature(encoded, message),
            expected,
            "raw_compressed/{status}",
        );

        verify.bench_function(format!("raw/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature(black_box(&affine), black_box(message)),
                )
            });
        });
        verify.bench_function(format!("pre_hashed/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature_pre_hashed(black_box(&affine), black_box(&hashed)),
                )
            });
        });
        verify.bench_function(format!("prepared/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature_prepared(black_box(&affine), black_box(&prepared)),
                )
            });
        });
        verify.bench_function(format!("raw_compressed/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature(black_box(encoded), black_box(message)),
                )
            });
        });
    }
    verify.finish();

    // Match the allocation test: aggregate two affine keys and signatures
    // inside each timed operation. Message preparation stays outside the
    // timed loop for the prepared path.
    let other_keypair = Keypair::derive(&[43u8; 32]).expect("derive second aggregate key");
    let aggregate_pubkeys = [keypair.public, other_keypair.public];
    let other_signature: SignatureAffine = other_keypair.sign(message).into();
    let aggregate_valid = [
        SignatureAffine::try_from(&valid).expect("decode first aggregate signature"),
        other_signature,
    ];
    let aggregate_wrong = [
        SignatureAffine::try_from(&wrong).expect("decode wrong-message aggregate signature"),
        other_signature,
    ];

    let mut aggregate = c.benchmark_group("bls_aggregate");
    for (status, signatures, expected) in [
        ("valid", &aggregate_valid, Ok(())),
        (
            "wrong_message",
            &aggregate_wrong,
            Err(BlsError::VerificationFailed),
        ),
    ] {
        assert_eq!(
            SignatureProjective::verify_aggregate(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                message,
            ),
            expected,
            "aggregate/raw/{status}",
        );
        assert_eq!(
            SignatureProjective::verify_aggregate_pre_hashed(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                &hashed,
            ),
            expected,
            "aggregate/pre_hashed/{status}",
        );
        assert_eq!(
            SignatureProjective::verify_aggregate_prepared(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                &prepared,
            ),
            expected,
            "aggregate/prepared/{status}",
        );

        aggregate.bench_function(format!("raw/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(message),
                ))
            });
        });
        aggregate.bench_function(format!("pre_hashed/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate_pre_hashed(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&hashed),
                ))
            });
        });
        aggregate.bench_function(format!("prepared/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate_prepared(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&prepared),
                ))
            });
        });
    }
    aggregate.finish();
}

#[cfg(feature = "parallel")]
fn time_on_worker(
    pool: &rayon::ThreadPool,
    iterations: u64,
    mut operation: impl FnMut() -> Result<(), BlsError> + Send,
) -> Duration {
    pool.install(move || {
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = black_box(operation());
        }
        start.elapsed()
    })
}

#[cfg(feature = "parallel")]
fn parallel_aggregate_paths(c: &mut Criterion) {
    let keypair = Keypair::derive(&[42u8; 32]).expect("derive fixture key");
    let other_keypair = Keypair::derive(&[43u8; 32]).expect("derive second fixture key");
    let message: &[u8] = b"solana-bls-signatures allocation baseline";
    let hashed = HashedMessage::new(message);
    let prepared = PreparedHashedMessage::from_hashed_message(&hashed);

    let public_keys = [keypair.public, other_keypair.public];
    let other_signature: SignatureAffine = other_keypair.sign(message).into();
    let valid_signatures: [SignatureAffine; 2] = [keypair.sign(message).into(), other_signature];
    let wrong_signatures: [SignatureAffine; 2] =
        [keypair.sign(b"a different message").into(), other_signature];

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("build parallel benchmark pool");

    // Match the allocation test's pool warm-up, outside the timed region.
    drop(pool.broadcast(|_| ()));
    std::thread::sleep(Duration::from_millis(100));

    println!("parallel aggregate timing: inside a private two-worker Rayon pool");
    println!("timing includes aggregation and verification; preparations are reused");

    let mut group = c.benchmark_group("bls_par_aggregate_worker");

    for (status, signatures, expected) in [
        ("valid", &valid_signatures, Ok(())),
        (
            "wrong_message",
            &wrong_signatures,
            Err(BlsError::VerificationFailed),
        ),
    ] {
        // Validate each path in the same worker context before timing it.
        pool.install(|| {
            assert_eq!(
                SignatureProjective::par_verify_aggregate(&public_keys, signatures, message,),
                expected,
                "parallel raw/{status}",
            );
            assert_eq!(
                SignatureProjective::par_verify_aggregate_pre_hashed(
                    &public_keys,
                    signatures,
                    &hashed,
                ),
                expected,
                "parallel pre_hashed/{status}",
            );
            assert_eq!(
                SignatureProjective::par_verify_aggregate_prepared(
                    &public_keys,
                    signatures,
                    &prepared,
                ),
                expected,
                "parallel prepared/{status}",
            );
        });

        group.bench_function(format!("raw/{status}"), |b| {
            b.iter_custom(|iterations| {
                time_on_worker(&pool, iterations, || {
                    SignatureProjective::par_verify_aggregate(
                        black_box(&public_keys),
                        black_box(signatures),
                        black_box(message),
                    )
                })
            });
        });

        group.bench_function(format!("pre_hashed/{status}"), |b| {
            b.iter_custom(|iterations| {
                time_on_worker(&pool, iterations, || {
                    SignatureProjective::par_verify_aggregate_pre_hashed(
                        black_box(&public_keys),
                        black_box(signatures),
                        black_box(&hashed),
                    )
                })
            });
        });

        group.bench_function(format!("prepared/{status}"), |b| {
            b.iter_custom(|iterations| {
                time_on_worker(&pool, iterations, || {
                    SignatureProjective::par_verify_aggregate_prepared(
                        black_box(&public_keys),
                        black_box(signatures),
                        black_box(&prepared),
                    )
                })
            });
        });
    }

    group.finish();
}

fn proof_of_possession_paths(c: &mut Criterion) {
    // Match the allocation regression fixtures and keep setup outside timing.
    let keypair = Keypair::derive(&[42u8; 32]).expect("derive PoP fixture key");
    let other_keypair = Keypair::derive(&[43u8; 32]).expect("derive other PoP key");
    let pubkey = *keypair.public;
    let pubkey_bytes = pubkey.to_bytes_compressed();
    let custom_payload: &[u8] = b"solana-pop-alloc";
    let mut group = c.benchmark_group("bls_pop");

    for (mode, payload) in [("standard", None), ("custom", Some(custom_payload))] {
        let payload_bytes = payload.unwrap_or(&[]);
        let hashed = HashedPoPPayload::new(payload_bytes, &pubkey_bytes);
        let valid: ProofOfPossessionAffine = keypair.proof_of_possession(payload).into();
        let wrong: ProofOfPossessionAffine = other_keypair.proof_of_possession(payload).into();

        group.bench_function(format!("hash/{mode}"), |b| {
            b.iter(|| {
                black_box(HashedPoPPayload::new(
                    black_box(payload_bytes),
                    black_box(&pubkey_bytes),
                ))
            });
        });

        for (status, proof, expected) in [
            ("valid", &valid, Ok(())),
            ("wrong_key", &wrong, Err(BlsError::VerificationFailed)),
        ] {
            assert_eq!(
                pubkey.verify_proof_of_possession(proof, payload),
                expected,
                "pop/raw/{mode}/{status}",
            );
            assert_eq!(
                pubkey.verify_proof_of_possession_pre_hashed(proof, &hashed),
                expected,
                "pop/pre_hashed/{mode}/{status}",
            );

            group.bench_function(format!("raw/{mode}/{status}"), |b| {
                b.iter(|| {
                    black_box(
                        black_box(&pubkey)
                            .verify_proof_of_possession(black_box(proof), black_box(payload)),
                    )
                });
            });
            group.bench_function(format!("pre_hashed/{mode}/{status}"), |b| {
                b.iter(|| {
                    black_box(black_box(&pubkey).verify_proof_of_possession_pre_hashed(
                        black_box(proof),
                        black_box(&hashed),
                    ))
                });
            });
        }
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);
    targets = verification_paths
}
criterion_main!(benches);
