//! Wrapper over `solana_hash::Hash` with wasm-bindgen
use {
    js_sys::{Array, Uint8Array},
    solana_hash::HASH_BYTES,
    std::{boxed::Box, format, string::String},
    wasm_bindgen::{prelude::*, JsCast},
};

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash {
    pub(crate) inner: solana_hash::Hash,
}

crate::conversion::impl_inner_conversion!(Hash, solana_hash::Hash);

#[allow(non_snake_case)]
#[wasm_bindgen]
impl Hash {
    /// Create a new Hash object
    ///
    /// * `value` - optional hash as a base58 encoded string, `Uint8Array`, `[number]`
    #[wasm_bindgen(constructor)]
    pub fn constructor(value: JsValue) -> Result<Self, JsValue> {
        if let Some(base58_str) = value.as_string() {
            base58_str
                .parse::<solana_hash::Hash>()
                .map(Into::into)
                .map_err(|x| JsValue::from(x.to_string()))
        } else if let Some(uint8_array) = value.dyn_ref::<Uint8Array>() {
            if uint8_array.length() as usize != HASH_BYTES {
                return Err(format!(
                    "Invalid Uint8Array length: expected {}, got {}",
                    HASH_BYTES,
                    uint8_array.length()
                )
                .into());
            }
            let mut bytes = [0u8; HASH_BYTES];
            uint8_array.copy_to(&mut bytes);
            Ok(solana_hash::Hash::new_from_array(bytes).into())
        } else if let Some(array) = value.dyn_ref::<Array>() {
            if array.length() as usize != HASH_BYTES {
                return Err(format!(
                    "Invalid Array length: expected {}, got {}",
                    HASH_BYTES,
                    array.length()
                )
                .into());
            }

            let mut bytes = [0u8; HASH_BYTES];
            let iterator = js_sys::try_iter(&array.values())?.expect("array to be iterable");
            for (i, x) in iterator.enumerate() {
                let x = x?;

                if let Some(n) = x.as_f64() {
                    if n >= 0. && n <= 255. {
                        bytes[i] = n as u8;
                        continue;
                    }
                }
                return Err(format!("Invalid array argument: {:?}", x).into());
            }
            Ok(solana_hash::Hash::new_from_array(bytes).into())
        } else if value.is_undefined() {
            Ok(solana_hash::Hash::default().into())
        } else {
            Err("Unsupported argument".into())
        }
    }

    /// Return the base58 string representation of the hash
    pub fn toString(&self) -> String {
        self.inner.to_string()
    }

    /// Checks if two `Hash`s are equal
    pub fn equals(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    /// Return the `Uint8Array` representation of the hash
    pub fn toBytes(&self) -> Box<[u8]> {
        self.inner.to_bytes().into()
    }
}
