#![allow(incomplete_features)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(specialization))]
// Activate some of the Rust 2024 lints to make the future migration easier.
#![warn(if_let_rescope)]
#![warn(keyword_idents_2024)]
#![warn(rust_2024_incompatible_pat)]
#![warn(tail_expr_drop_order)]
#![warn(unsafe_attr_outside_unsafe)]
#![warn(unsafe_op_in_unsafe_fn)]

// Allows macro expansion of `use ::solana_frozen_abi::*` to work within this crate
extern crate self as solana_frozen_abi;

#[cfg(feature = "frozen-abi")]
pub mod abi_digester;
#[cfg(feature = "frozen-abi")]
pub mod abi_example;
#[cfg(feature = "frozen-abi")]
pub mod hash;

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
pub mod stable_abi;

#[cfg(feature = "frozen-abi")]
#[macro_use]
extern crate solana_frozen_abi_macro;

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
pub use {bincode, rand, rand_chacha};

// Not public API. Previously referenced by macro-generated code. Remove the
// `log` dependency from Cargo.toml when this is cleaned up in the next major
// version bump
#[deprecated(since = "3.0.1", note = "Please use the `log` crate directly instead")]
#[doc(hidden)]
pub mod __private {
    #[doc(hidden)]
    pub use log;
}

#[cfg_attr(
    all(not(target_os = "solana"), feature = "frozen-abi"),
    frozen_abi(
        api_digest = "3ZRPJYbEUp8VCES2v33cV6T3DtqqT1xe6HWjRmNzQy8L",
        abi_digest = "9nFE49FJPx9gCu1HCZuw6RtFZQtuRc9LWpahg2j93Ugp"
    ),
    derive(AbiExample, StableAbi)
)]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestStruct {
    sample_u8: u8,
    sample_u16: u16,
    sample_u32: u32,
    sample_u64: u64,
    sample_u128: u128,
    sample_i8: i8,
    sample_i16: i16,
    sample_i32: i32,
    sample_i64: i64,
    sample_i128: i128,
    sample_f32: f32,
    sample_f64: f64,
    sample_bool: bool,
    sample_char: char,
    sample_bytes: [u8; 32],
    sample_tuple: (u8, u16, i32, bool),
}

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
impl solana_frozen_abi::rand::distr::Distribution<TestStruct>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStruct {
        TestStruct {
            sample_u8: rng.random(),
            sample_u16: rng.random(),
            sample_u32: rng.random(),
            sample_u64: rng.random(),
            sample_u128: rng.random(),
            sample_i8: rng.random(),
            sample_i16: rng.random(),
            sample_i32: rng.random(),
            sample_i64: rng.random(),
            sample_i128: rng.random(),
            sample_f32: rng.random(),
            sample_f64: rng.random(),
            sample_bool: rng.random(),
            sample_char: rng.random(),
            sample_bytes: rng.random(),
            sample_tuple: (rng.random(), rng.random(), rng.random(), rng.random()),
        }
    }
}

#[cfg_attr(
    all(not(target_os = "solana"), feature = "frozen-abi"),
    frozen_abi(
        api_digest = "ikrz9ZPK59Wr2Zk5ujBLVP6P7qwgZA5oRWVBoWbMnDT",
        abi_digest = "8RY4t5qa1PnwuUfEWssUKcyNkFoyvjma5YVNd24eHeSa"
    ),
    derive(AbiExample, StableAbi)
)]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestStruct2 {
    id: u64,
    name: [u8; 16],
    flags: (bool, bool, bool),
    list: Vec<u32>,
    matrix: [[f32; 4]; 4],
}

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
impl solana_frozen_abi::rand::distr::Distribution<TestStruct2>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStruct2 {
        TestStruct2 {
            id: rng.random(),
            name: rng.random(),
            flags: (rng.random(), rng.random(), rng.random()),
            list: (0..rng.random_range(0..10))
                .map(|_| rng.random::<u32>())
                .collect(),
            matrix: std::array::from_fn(|_| std::array::from_fn(|_| rng.random())),
        }
    }
}

#[cfg_attr(
    all(not(target_os = "solana"), feature = "frozen-abi"),
    frozen_abi(
        api_digest = "5PPaKztQfSF2zK2An2XCjLJu4yWhBJQfpMzCVcsSksJE",
        abi_digest = "4BPojpfLCiXzb8tdMJTfAe5gR6zsi8ejZZGoU8ybghmY"
    ),
    derive(AbiExample, StableAbi, AbiEnumVisitor)
)]
#[derive(serde::Serialize, serde::Deserialize)]
enum TestEnum {
    A(u8),
    B(i64, bool),
    C { x: f32, y: f64 },
}

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
impl solana_frozen_abi::rand::distr::Distribution<TestEnum>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestEnum {
        match rng.random_range(0..3) {
            0 => TestEnum::A(rng.random()),
            1 => TestEnum::B(rng.random(), rng.random()),
            _ => TestEnum::C {
                x: rng.random(),
                y: rng.random(),
            },
        }
    }
}

#[cfg_attr(
    all(not(target_os = "solana"), feature = "frozen-abi"),
    frozen_abi(
        api_digest = "7uB2AxzhZzj5ZEnLhxK7r8RkxNXQCYaAv9wNxMRdxjtC",
        abi_digest = "9nxf1FgoAsEDAgnMadYaTpWvxyhoEHgFogpdSsrj3Bu5"
    ),
    derive(AbiExample, StableAbi)
)]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestStruct3 {
    maybe_enum: Option<TestEnum>,
    vector: Vec<i16>,
    tuple_array: [(u32, bool); 8],
}

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
impl solana_frozen_abi::rand::distr::Distribution<TestStruct3>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStruct3 {
        let variant: u8 = rng.random_range(0..3);
        let maybe_enum = match variant {
            0 => Some(TestEnum::A(rng.random())),
            1 => Some(TestEnum::B(rng.random(), rng.random())),
            2 => Some(TestEnum::C {
                x: rng.random(),
                y: rng.random(),
            }),
            _ => None,
        };

        TestStruct3 {
            maybe_enum,
            vector: (0..rng.random_range(0..5))
                .map(|_| rng.random::<i16>())
                .collect(),
            tuple_array: std::array::from_fn(|_| (rng.random(), rng.random())),
        }
    }
}

#[cfg_attr(
    all(not(target_os = "solana"), feature = "frozen-abi"),
    frozen_abi(
        api_digest = "2VBMowc8TA1aLT4cLqo2K1AKBsJ2nw3tBzVuKGiq7FWo",
        abi_digest = "5kT8YRqxwSZsfknXqLDt2DMhMQCifUd91CTtgx2MAkSY"
    ),
    derive(AbiExample, StableAbi)
)]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestStruct4 {
    inner: TestStruct,
    nested: Vec<TestStruct2>,
    complex: Option<TestStruct3>,
}

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
impl solana_frozen_abi::rand::distr::Distribution<TestStruct4>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> TestStruct4 {
        TestStruct4 {
            inner: rng.random(),
            nested: (0..rng.random_range(0..3))
                .map(|_| rng.random::<TestStruct2>())
                .collect(),
            complex: if rng.random() {
                Some(rng.random::<TestStruct3>())
            } else {
                None
            },
        }
    }
}
