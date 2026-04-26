#[cfg(feature = "parallel")]
use rayon::prelude::*;
use {
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion},
    ed25519_dalek::Signer,
    solana_signature::Signature,
    std::vec::Vec,
};

const BATCH_SIZES: [usize; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512];

struct BenchData {
    messages: Vec<Vec<u8>>,
    signatures: Vec<Signature>,
    pubkeys: Vec<[u8; 32]>,
}

fn create_bench_data(size: usize) -> BenchData {
    let signing_keys: Vec<_> = (0..size)
        .map(|i| {
            let key_index = i.checked_add(1).unwrap();
            let key_index_bytes = key_index.to_le_bytes();
            let mut bytes = [0; 32];
            bytes[..key_index_bytes.len()].copy_from_slice(&key_index_bytes);
            ed25519_dalek::SigningKey::from_bytes(&bytes)
        })
        .collect();
    let messages: Vec<_> = (0..size)
        .map(|i| format!("solana-signature-bench-message-{i}").into_bytes())
        .collect();
    let signatures = signing_keys
        .iter()
        .zip(messages.iter())
        .map(|(signing_key, message)| Signature::from(signing_key.sign(message).to_bytes()))
        .collect();
    let pubkeys = signing_keys
        .iter()
        .map(|signing_key| signing_key.verifying_key().to_bytes())
        .collect();

    BenchData {
        messages,
        signatures,
        pubkeys,
    }
}

fn signature_data(data: &BenchData) -> impl Iterator<Item = (&Signature, &[u8], &[u8])> {
    data.signatures
        .iter()
        .zip(data.pubkeys.iter())
        .zip(data.messages.iter())
        .map(|((signature, pubkey), message)| (signature, pubkey.as_slice(), message.as_slice()))
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verify");

    for size in BATCH_SIZES {
        let data = create_bench_data(size);

        group.bench_with_input(BenchmarkId::new("individual", size), &data, |b, data| {
            b.iter(|| {
                for (signature, (pubkey, message)) in data
                    .signatures
                    .iter()
                    .zip(data.pubkeys.iter().zip(data.messages.iter()))
                {
                    assert!(black_box(signature)
                        .verify(black_box(pubkey.as_slice()), black_box(message.as_slice()),));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("batch", size), &data, |b, data| {
            b.iter(|| {
                assert!(Signature::batch_verify(black_box(signature_data(data))));
            });
        });

        #[cfg(feature = "parallel")]
        group.bench_with_input(
            BenchmarkId::new("par_individual", size),
            &data,
            |b, data| {
                b.iter(|| {
                    assert!(data
                        .signatures
                        .par_iter()
                        .zip(data.pubkeys.par_iter())
                        .zip(data.messages.par_iter())
                        .all(|((signature, pubkey), message)| black_box(signature)
                            .verify(black_box(pubkey.as_slice()), black_box(message.as_slice()),)));
                });
            },
        );

        #[cfg(feature = "parallel")]
        group.bench_with_input(BenchmarkId::new("par_batch", size), &data, |b, data| {
            b.iter(|| {
                assert!(Signature::par_batch_verify(black_box(signature_data(data))));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
