use solana_bls12_381::{Endianness, GtElement, GT_ELEMENT_SIZE};

#[test]
fn identity_comparison_checks_every_bit_at_any_alignment() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let identity = GtElement::identity(endianness);
        for offset in 0..8 {
            let mut buffer = [0xa5; GT_ELEMENT_SIZE + 7];
            let bytes: &mut [u8; GT_ELEMENT_SIZE] = (&mut buffer[offset..][..GT_ELEMENT_SIZE])
                .try_into()
                .unwrap();
            bytes.copy_from_slice(identity.as_bytes());
            assert!(GtElement::from_bytes_ref(bytes).is_identity(endianness));

            for byte in 0..GT_ELEMENT_SIZE {
                for bit in 0..8 {
                    bytes[byte] ^= 1 << bit;
                    assert!(
                        !GtElement::from_bytes_ref(bytes).is_identity(endianness),
                        "{endianness:?}, offset {offset}, byte {byte}, bit {bit}"
                    );
                    bytes[byte] ^= 1 << bit;
                }
            }
        }
    }
}

#[test]
fn identity_comparison_rejects_the_other_byte_order() {
    let little = GtElement::identity(Endianness::Little);
    let big = GtElement::identity(Endianness::Big);
    assert!(!little.is_identity(Endianness::Big));
    assert!(!big.is_identity(Endianness::Little));
}
