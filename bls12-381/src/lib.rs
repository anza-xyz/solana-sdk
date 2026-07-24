#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod g1;
pub mod g2;
pub mod pairing;
pub mod scalar;

pub use {g1::*, g2::*, pairing::*, scalar::*};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}
