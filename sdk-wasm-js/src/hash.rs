//! Wrapper over `solana_hash::Hash` with wasm-bindgen
use {
    js_sys::{Array, Uint8Array},
    std::{boxed::Box, format, string::String, vec},
    wasm_bindgen::{prelude::*, JsCast},
};

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Hash(pub(crate) solana_hash::Hash);

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
                .map(Hash)
                .map_err(|x| JsValue::from(x.to_string()))
        } else if let Some(uint8_array) = value.dyn_ref::<Uint8Array>() {
            <[u8; solana_hash::HASH_BYTES]>::try_from(uint8_array.to_vec())
                .map(solana_hash::Hash::new_from_array)
                .map(Hash)
                .map_err(|err| format!("Invalid Hash value: {err:?}").into())
        } else if let Some(array) = value.dyn_ref::<Array>() {
            let mut bytes = vec![];
            let iterator = js_sys::try_iter(&array.values())?.expect("array to be iterable");
            for x in iterator {
                let x = x?;

                if let Some(n) = x.as_f64() {
                    if n >= 0. && n <= 255. {
                        bytes.push(n as u8);
                        continue;
                    }
                }
                return Err(format!("Invalid array argument: {:?}", x).into());
            }
            <[u8; solana_hash::HASH_BYTES]>::try_from(bytes)
                .map(solana_hash::Hash::new_from_array)
                .map(Hash)
                .map_err(|err| format!("Invalid Hash value: {err:?}").into())
        } else if value.is_undefined() {
            Ok(Hash(solana_hash::Hash::default()))
        } else {
            Err("Unsupported argument".into())
        }
    }

    /// Return the base58 string representation of the hash
    pub fn toString(&self) -> String {
        self.0.to_string()
    }

    /// Checks if two `Hash`s are equal
    pub fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Return the `Uint8Array` representation of the hash
    pub fn toBytes(&self) -> Box<[u8]> {
        self.0.to_bytes().into()
    }
}
