//! Address wrapper

use {
    crate::display_to_jsvalue,
    js_sys::{Array, Uint8Array},
    solana_address::{ADDRESS_BYTES, MAX_SEEDS, MAX_SEED_LEN},
    wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue},
};

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Address {
    pub(crate) inner: solana_address::Address,
}

crate::conversion::impl_inner_conversion!(Address, solana_address::Address);

fn js_value_to_seeds_vec(array_of_uint8_arrays: &[JsValue]) -> Result<Vec<Vec<u8>>, JsValue> {
    if array_of_uint8_arrays.len() > MAX_SEEDS {
        return Err(JsValue::from(std::format!(
            "Too many seeds: {} > {}",
            array_of_uint8_arrays.len(),
            MAX_SEEDS
        )));
    }

    array_of_uint8_arrays
        .iter()
        .enumerate()
        .map(|(i, u8_array_js)| {
            let u8_array = u8_array_js
                .dyn_ref::<Uint8Array>()
                .ok_or_else(|| JsValue::from(std::format!("Invalid seed type at index {}", i)))?;
            if u8_array.length() as usize > MAX_SEED_LEN {
                return Err(JsValue::from(std::format!(
                    "Seed {} too long: {} > {}",
                    i,
                    u8_array.length(),
                    MAX_SEED_LEN
                )));
            }

            Ok(u8_array.to_vec())
        })
        .collect::<Result<Vec<_>, _>>()
}

#[allow(non_snake_case)]
#[wasm_bindgen]
impl Address {
    /// Create a new Address object
    ///
    /// * `value` - optional public key as a base58 encoded string, `Uint8Array`, `[number]`
    #[wasm_bindgen(constructor)]
    pub fn constructor(value: JsValue) -> Result<Self, JsValue> {
        if let Some(base58_str) = value.as_string() {
            base58_str
                .parse::<solana_address::Address>()
                .map(Into::into)
                .map_err(display_to_jsvalue)
        } else if let Some(uint8_array) = value.dyn_ref::<Uint8Array>() {
            if uint8_array.length() as usize != ADDRESS_BYTES {
                return Err(std::format!(
                    "Invalid Uint8Array length: expected {}, got {}",
                    ADDRESS_BYTES,
                    uint8_array.length()
                )
                .into());
            }
            let mut bytes = [0u8; ADDRESS_BYTES];
            uint8_array.copy_to(&mut bytes);
            Ok(solana_address::Address::new_from_array(bytes).into())
        } else if let Some(array) = value.dyn_ref::<Array>() {
            if array.length() as usize != ADDRESS_BYTES {
                return Err(std::format!(
                    "Invalid Array length: expected {}, got {}",
                    ADDRESS_BYTES,
                    array.length()
                )
                .into());
            }
            let mut bytes = [0u8; ADDRESS_BYTES];
            let iterator = js_sys::try_iter(&array.values())?.expect("array to be iterable");
            for (i, x) in iterator.enumerate() {
                let x = x?;

                if let Some(n) = x.as_f64() {
                    if n >= 0. && n <= 255. {
                        bytes[i] = n as u8;
                        continue;
                    }
                }
                return Err(std::format!("Invalid array argument: {:?}", x).into());
            }
            Ok(solana_address::Address::new_from_array(bytes).into())
        } else if value.is_undefined() {
            Ok(solana_address::Address::default().into())
        } else {
            Err("Unsupported argument".into())
        }
    }

    /// Return the base58 string representation of the public key
    pub fn toString(&self) -> std::string::String {
        std::string::ToString::to_string(&self.inner)
    }

    /// Check if a `Address` is on the ed25519 curve.
    pub fn isOnCurve(&self) -> bool {
        self.inner.is_on_curve()
    }

    /// Checks if two `Address`s are equal
    pub fn equals(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    /// Return the `Uint8Array` representation of the public key
    pub fn toBytes(&self) -> std::boxed::Box<[u8]> {
        self.inner.to_bytes().into()
    }

    /// Derive an Address from anothern Address, string seed, and a program id
    pub fn createWithSeed(base: &Self, seed: &str, owner: &Self) -> Result<Self, JsValue> {
        solana_address::Address::create_with_seed(&base.inner, seed, &owner.inner)
            .map(Into::into)
            .map_err(display_to_jsvalue)
    }

    /// Derive a program address from seeds and a program id
    pub fn createProgramAddress(
        seeds: std::boxed::Box<[JsValue]>,
        program_id: &Self,
    ) -> Result<Self, JsValue> {
        let seeds_vec = js_value_to_seeds_vec(&seeds)?;
        let seeds_slice = seeds_vec
            .iter()
            .map(|seed| seed.as_slice())
            .collect::<Vec<_>>();

        solana_address::Address::create_program_address(seeds_slice.as_slice(), &program_id.inner)
            .map(Into::into)
            .map_err(display_to_jsvalue)
    }

    /// Find a valid program address
    ///
    /// Returns:
    /// * `[Address, number]` - the program address and bump seed
    pub fn findProgramAddress(
        seeds: std::boxed::Box<[JsValue]>,
        program_id: &Self,
    ) -> Result<JsValue, JsValue> {
        let seeds_vec = js_value_to_seeds_vec(&seeds)?;
        let seeds_slice = seeds_vec
            .iter()
            .map(|seed| seed.as_slice())
            .collect::<Vec<_>>();

        let (address, bump_seed) = solana_address::Address::find_program_address(
            seeds_slice.as_slice(),
            &program_id.inner,
        );

        let result = Array::new_with_length(2);
        result.set(0, Address::from(address).into());
        result.set(1, bump_seed.into());
        Ok(result.into())
    }
}
