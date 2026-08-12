#![feature(test)]

extern crate test;
use {solana_sdk::slot_history::SlotHistory, test::Bencher};

#[bench]
fn bench_slot_history_add_new(b: &mut Bencher) {
    let mut slot_history = SlotHistory::default();

    let mut slot = 0;
    b.iter(|| {
        for _ in 0..5 {
            slot_history.add(slot);
            slot += 100_000;
        }
    });
}
