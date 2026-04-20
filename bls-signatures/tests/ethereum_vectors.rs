use {
    blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar},
    group::{prime::PrimeCurveAffine, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
    serde_json::Value,
    solana_bls_signatures::{
        hash::HASH_TO_POINT_DST,
        pubkey::{PopVerified, PubkeyAffineUnchecked, PubkeyCompressed, VerifySignature},
        signature::SignatureAffine,
        SecretKey, SignatureCompressed, SignatureProjective,
    },
    std::{
        ffi::OsStr,
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::OnceLock,
        vec::Vec,
    },
};

const ETHEREUM_BLS_TESTS_VERSION: &str = "v0.1.2";

fn fixtures_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        if let Some(root) = std::env::var_os("ETHEREUM_BLS_TESTS_DIR") {
            return PathBuf::from(root);
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target")
            .join("test-fixtures")
            .join("ethereum-bls")
            .join(ETHEREUM_BLS_TESTS_VERSION);
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fetch_ethereum_vectors.py");
        let status = Command::new("python3")
            .arg(script)
            .arg("--output-dir")
            .arg(&root)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to fetch Ethereum BLS test vectors into {}",
            root.display()
        );
        root
    })
}

fn fixtures_dir(handler: &str) -> PathBuf {
    fixtures_root().join(handler)
}

fn json_files(handler: &str) -> Vec<PathBuf> {
    let mut files = fs::read_dir(fixtures_dir(handler))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() == Some(OsStr::new("json")))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn load_case(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn fixed_hex_bytes<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(encoded.trim_start_matches("0x")).ok()?;
    bytes.try_into().ok()
}

fn hex_vec(encoded: &str) -> Vec<u8> {
    hex::decode(encoded.trim_start_matches("0x")).unwrap()
}

fn parse_g1(encoded: &str) -> Option<G1Affine> {
    let bytes = fixed_hex_bytes::<48>(encoded)?;
    Option::<G1Affine>::from(G1Affine::from_compressed(&bytes))
}

fn parse_g2(encoded: &str) -> Option<G2Affine> {
    let bytes = fixed_hex_bytes::<96>(encoded)?;
    Option::<G2Affine>::from(G2Affine::from_compressed(&bytes))
}

fn deterministic_batch_verify(
    pubkeys: &[String],
    messages: &[Vec<u8>],
    signatures: &[String],
) -> bool {
    if pubkeys.len() != messages.len() || pubkeys.len() != signatures.len() || pubkeys.is_empty() {
        return false;
    }

    let Some(pubkeys) = pubkeys
        .iter()
        .map(|pubkey| parse_g1(pubkey))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if pubkeys
        .iter()
        .any(|pubkey| bool::from(pubkey.is_identity()))
    {
        return false;
    }

    let Some(signatures) = signatures
        .iter()
        .map(|signature| parse_g2(signature))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };

    let scalars = (1..=pubkeys.len())
        .map(|index| Scalar::from(index as u64))
        .collect::<Vec<_>>();

    #[allow(clippy::arithmetic_side_effects)]
    let weighted_pubkeys = pubkeys
        .iter()
        .zip(&scalars)
        .map(|(pubkey, scalar)| G1Affine::from(G1Projective::from(*pubkey) * scalar))
        .collect::<Vec<_>>();
    #[allow(clippy::arithmetic_side_effects)]
    let weighted_signature = signatures
        .iter()
        .zip(&scalars)
        .fold(G2Projective::identity(), |acc, (signature, scalar)| {
            acc + G2Projective::from(*signature) * scalar
        });
    let weighted_signature_prepared = G2Prepared::from(G2Affine::from(weighted_signature));
    let hashed_messages = messages
        .iter()
        .map(|message| {
            G2Prepared::from(G2Affine::from(G2Projective::hash_to_curve(
                message,
                HASH_TO_POINT_DST,
                &[],
            )))
        })
        .collect::<Vec<_>>();
    #[allow(clippy::arithmetic_side_effects)]
    let neg_g1_generator: G1Affine = (-G1Projective::generator()).into();

    let mut terms = weighted_pubkeys
        .iter()
        .zip(&hashed_messages)
        .collect::<Vec<_>>();
    terms.push((&neg_g1_generator, &weighted_signature_prepared));

    Bls12::multi_miller_loop(&terms).final_exponentiation() == Gt::identity()
}

#[test]
fn ethereum_sign_vectors() {
    for path in json_files("sign") {
        let case = load_case(&path);
        let input = &case["input"];
        let message = hex_vec(input["message"].as_str().unwrap());

        let mut secret_bytes = fixed_hex_bytes::<32>(input["privkey"].as_str().unwrap()).unwrap();
        // Ethereum vectors encode secret scalars big-endian; this crate's parser expects LE.
        secret_bytes.reverse();

        let actual = SecretKey::try_from(secret_bytes.as_slice())
            .map(|secret| {
                let signature = secret.sign(&message);
                let affine: SignatureAffine = signature.into();
                let compressed: SignatureCompressed = affine.into();
                compressed.0
            })
            .ok();

        let expected = case["output"]
            .as_str()
            .map(|output| fixed_hex_bytes::<96>(output).unwrap());
        assert_eq!(actual, expected, "fixture {}", path.display());
    }
}

#[test]
fn ethereum_verify_vectors() {
    for path in json_files("verify") {
        let case = load_case(&path);
        let input = &case["input"];

        let pubkey = unsafe {
            PopVerified::new_unchecked(PubkeyCompressed(
                fixed_hex_bytes(input["pubkey"].as_str().unwrap()).unwrap(),
            ))
        };
        let message = hex_vec(input["message"].as_str().unwrap());
        let signature =
            SignatureCompressed(fixed_hex_bytes(input["signature"].as_str().unwrap()).unwrap());

        let verified = pubkey.verify_signature(&signature, &message).is_ok();
        assert_eq!(
            verified,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}

#[test]
fn ethereum_aggregate_vectors() {
    for path in json_files("aggregate") {
        let case = load_case(&path);
        let signatures = case["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|signature| {
                SignatureCompressed(fixed_hex_bytes(signature.as_str().unwrap()).unwrap())
            })
            .collect::<Vec<_>>();

        let actual = SignatureProjective::aggregate(signatures.iter())
            .map(|aggregate| {
                let affine: SignatureAffine = aggregate.into();
                let compressed: SignatureCompressed = affine.into();
                compressed.0
            })
            .ok();

        let expected = case["output"]
            .as_str()
            .map(|output| fixed_hex_bytes::<96>(output).unwrap());
        assert_eq!(actual, expected, "fixture {}", path.display());
    }
}

#[test]
fn ethereum_aggregate_verify_vectors() {
    for path in json_files("aggregate_verify") {
        let case = load_case(&path);
        let input = &case["input"];

        let pubkeys = input["pubkeys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|pubkey| {
                fixed_hex_bytes(pubkey.as_str().unwrap())
                    .map(|pubkey| unsafe { PopVerified::new_unchecked(PubkeyCompressed(pubkey)) })
            })
            .collect::<Vec<_>>();
        let messages = input["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| hex_vec(message.as_str().unwrap()))
            .collect::<Vec<_>>();
        let verified = fixed_hex_bytes(input["signature"].as_str().unwrap())
            .map(SignatureCompressed)
            .map(|signature| {
                SignatureProjective::verify_distinct_aggregated(
                    pubkeys.iter(),
                    &signature,
                    messages.iter().map(Vec::as_slice),
                )
                .is_ok()
            })
            .unwrap_or(false);

        assert_eq!(
            verified,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}

#[test]
fn ethereum_fast_aggregate_verify_vectors() {
    for path in json_files("fast_aggregate_verify") {
        let case = load_case(&path);
        let input = &case["input"];

        let pubkeys = input["pubkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pubkey| unsafe {
                PopVerified::new_unchecked(PubkeyCompressed(
                    fixed_hex_bytes(pubkey.as_str().unwrap()).unwrap(),
                ))
            })
            .collect::<Vec<_>>();
        let message = hex_vec(input["message"].as_str().unwrap());
        let signature =
            SignatureCompressed(fixed_hex_bytes(input["signature"].as_str().unwrap()).unwrap());

        let verified = SignatureProjective::verify_aggregate(
            pubkeys.iter(),
            core::iter::once(&signature),
            &message,
        )
        .is_ok();

        assert_eq!(
            verified,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}

#[test]
fn ethereum_batch_verify_vectors() {
    for path in json_files("batch_verify") {
        let case = load_case(&path);
        let input = &case["input"];

        let pubkeys = input["pubkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pubkey| pubkey.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let messages = input["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| hex_vec(message.as_str().unwrap()))
            .collect::<Vec<_>>();
        let signatures = input["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|signature| signature.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        let verified = deterministic_batch_verify(&pubkeys, &messages, &signatures);

        assert_eq!(
            verified,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}

#[test]
fn ethereum_g1_deserialization_vectors() {
    for path in json_files("deserialization_G1") {
        let case = load_case(&path);
        let actual = fixed_hex_bytes(case["input"]["pubkey"].as_str().unwrap())
            .map(PubkeyCompressed)
            .map(|encoded| {
                PubkeyAffineUnchecked::try_from(&encoded)
                    .and_then(|pubkey| pubkey.verify_subgroup())
                    .is_ok()
            })
            .unwrap_or(false);

        assert_eq!(
            actual,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}

#[test]
fn ethereum_g2_deserialization_vectors() {
    for path in json_files("deserialization_G2") {
        let case = load_case(&path);
        let actual = fixed_hex_bytes(case["input"]["signature"].as_str().unwrap())
            .map(SignatureCompressed)
            .map(|encoded| SignatureAffine::try_from(&encoded).is_ok())
            .unwrap_or(false);

        assert_eq!(
            actual,
            case["output"].as_bool().unwrap(),
            "fixture {}",
            path.display()
        );
    }
}
