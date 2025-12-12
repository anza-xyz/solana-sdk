use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bls_signatures::{
        keypair::Keypair,
        pubkey::{Pubkey, PubkeyProjective, VerifiablePubkey},
        signature::{Signature, SignatureProjective},
    },
    std::hint::black_box,
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
            .map(|kp| PubkeyProjective::from(&kp.public))
            .collect();

        let signatures: Vec<SignatureProjective> =
            keypairs.iter().map(|kp| kp.sign(message)).collect();

        // Benchmark for aggregating multiple signatures
        group.bench_function(format!("{num_validators} signature aggregation"), |b| {
            b.iter(|| black_box(SignatureProjective::aggregate(signatures.iter())));
        });

        #[cfg(feature = "parallel")]
        {
            // Create references for parallel benchmark
            let signature_refs: Vec<&SignatureProjective> = signatures.iter().collect();

            group.bench_function(
                format!("{num_validators} parallel signature aggregation"),
                |b| {
                    use rayon::prelude::*;
                    b.iter(|| {
                        black_box(SignatureProjective::par_aggregate(
                            signature_refs.par_iter().cloned(),
                        ))
                    });
                },
            );
        }

        // Benchmark for aggregating multiple public keys
        group.bench_function(format!("{num_validators} pubkey aggregation"), |b| {
            b.iter(|| black_box(PubkeyProjective::aggregate(pubkeys.iter())));
        });

        #[cfg(feature = "parallel")]
        {
            let pubkey_refs: Vec<&PubkeyProjective> = pubkeys.iter().collect();

            group.bench_function(
                format!("{num_validators} parallel pubkey aggregation"),
                |b| {
                    use rayon::prelude::*;
                    b.iter(|| {
                        black_box(PubkeyProjective::par_aggregate(
                            pubkey_refs.par_iter().cloned(),
                        ))
                    });
                },
            );
        }

        group.bench_function(
            format!("{num_validators} sequential aggregate verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::verify_aggregate(
                            pubkeys.iter(),
                            signatures.iter(),
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
                        SignatureProjective::par_verify_aggregate(&pubkeys, &signatures, message)
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
    let pop = keypair.proof_of_possession(None);

    c.bench_function("proof_of_possession_creation", |b| {
        b.iter(|| black_box(keypair.proof_of_possession(None)));
    });

    c.bench_function("proof_of_possession_verification", |b| {
        b.iter(|| {
            black_box(keypair.public.verify_proof_of_possession(&pop, None)).unwrap();
        })
    });
}

// Benchmark for batch verification functions
fn bench_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify");

    for num_validators in [64, 128, 256, 512, 1024, 2048].iter() {
        let keypairs: Vec<Keypair> = (0..*num_validators).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<Pubkey> = keypairs.iter().map(|kp| kp.public.into()).collect();

        // Create a unique message for each validator
        let messages: Vec<Vec<u8>> = (0..*num_validators)
            .map(|i| format!("message_{i}").into_bytes())
            .collect();

        // Create a signature for each message
        let signatures: Vec<Signature> = keypairs
            .iter()
            .zip(messages.iter())
            .map(|(kp, msg)| kp.sign(msg).into())
            .collect();

        group.bench_function(
            format!("{num_validators} sequential batch verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::verify_distinct(
                            pubkeys.iter(),
                            signatures.iter(),
                            messages.iter().map(Vec::as_slice),
                        )
                        .unwrap(),
                    );
                    assert!(verification_result);
                });
            },
        );

        #[cfg(feature = "parallel")]
        {
            let message_refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

            group.bench_function(
                format!("{num_validators} parallel batch verification"),
                |b| {
                    b.iter(|| {
                        let verification_result = black_box(
                            SignatureProjective::par_verify_distinct(
                                &pubkeys,
                                &signatures,
                                &message_refs,
                            )
                            .unwrap(),
                        );
                        assert!(verification_result);
                    });
                },
            );
        }
    }
    group.finish()
}

criterion_group!(
    benches,
    bench_single_signature,
    bench_aggregate,
    bench_key_generation,
    bench_proof_of_possession,
    bench_batch_verification
);
criterion_main!(benches);
