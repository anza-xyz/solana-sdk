//! Address wrapper

use {
    crate::display_to_jsvalue,
    js_sys::{Array, Uint8Array},
    wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue},
};

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Address(pub(crate) solana_address::Address);

fn js_value_to_seeds_vec(array_of_uint8_arrays: &[JsValue]) -> Result<Vec<Vec<u8>>, JsValue> {
    let vec_vec_u8 = array_of_uint8_arrays
        .iter()
        .filter_map(|u8_array| {
            u8_array
                .dyn_ref::<Uint8Array>()
                .map(|u8_array| u8_array.to_vec())
        })
        .collect::<Vec<_>>();

    if vec_vec_u8.len() != array_of_uint8_arrays.len() {
        Err("Invalid Array of Uint8Arrays".into())
    } else {
        Ok(vec_vec_u8)
    }
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
                .map(Self)
                .map_err(display_to_jsvalue)
        } else if let Some(uint8_array) = value.dyn_ref::<Uint8Array>() {
            solana_address::Address::try_from(uint8_array.to_vec())
                .map(Self)
                .map_err(|err| JsValue::from(std::format!("Invalid Uint8Array address: {err:?}")))
        } else if let Some(array) = value.dyn_ref::<Array>() {
            let mut bytes = std::vec![];
            let iterator = js_sys::try_iter(&array.values())?.expect("array to be iterable");
            for x in iterator {
                let x = x?;

                if let Some(n) = x.as_f64() {
                    if n >= 0. && n <= 255. {
                        bytes.push(n as u8);
                        continue;
                    }
                }
                return Err(std::format!("Invalid array argument: {:?}", x).into());
            }
            solana_address::Address::try_from(bytes)
                .map(Self)
                .map_err(|err| JsValue::from(std::format!("Invalid Array address: {err:?}")))
        } else if value.is_undefined() {
            Ok(Self(solana_address::Address::default()))
        } else {
            Err("Unsupported argument".into())
        }
    }

    /// Return the base58 string representation of the public key
    pub fn toString(&self) -> std::string::String {
        std::string::ToString::to_string(&self.0)
    }

    /// Check if a `Address` is on the ed25519 curve.
    pub fn isOnCurve(&self) -> bool {
        self.0.is_on_curve()
    }

    /// Checks if two `Address`s are equal
    pub fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Return the `Uint8Array` representation of the public key
    pub fn toBytes(&self) -> std::boxed::Box<[u8]> {
        self.0.to_bytes().into()
    }

    /// Derive an Address from anothern Address, string seed, and a program id
    pub fn createWithSeed(base: &Self, seed: &str, owner: &Self) -> Result<Self, JsValue> {
        solana_address::Address::create_with_seed(&base.0, seed, &owner.0)
            .map(Self)
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

        solana_address::Address::create_program_address(seeds_slice.as_slice(), &program_id.0)
            .map(Self)
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

        let (address, bump_seed) =
            solana_address::Address::find_program_address(seeds_slice.as_slice(), &program_id.0);

        let result = Array::new_with_length(2);
        result.set(0, Self(address).into());
        result.set(1, bump_seed.into());
        Ok(result.into())
    }
}
