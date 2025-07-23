use {
    crate::Address,
    js_sys::{Array, Uint8Array},
    std::{fmt, vec::Vec},
    wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue},
};

#[cfg(feature = "curve25519")]
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

fn display_to_jsvalue<T: fmt::Display>(display: T) -> JsValue {
    std::string::ToString::to_string(&display).into()
}

#[allow(non_snake_case)]
#[wasm_bindgen]
impl Address {
    /// Create a new Address object
    ///
    /// * `value` - optional address as a base58 encoded string, `Uint8Array`, `[number]`
    #[wasm_bindgen(constructor)]
    pub fn constructor(value: JsValue) -> Result<Address, JsValue> {
        if let Some(base58_str) = value.as_string() {
            base58_str.parse::<Address>().map_err(display_to_jsvalue)
        } else if let Some(uint8_array) = value.dyn_ref::<Uint8Array>() {
            Address::try_from(uint8_array.to_vec())
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
            Address::try_from(bytes)
                .map_err(|err| JsValue::from(std::format!("Invalid Array address: {err:?}")))
        } else if value.is_undefined() {
            Ok(Address::default())
        } else {
            Err("Unsupported argument".into())
        }
    }

    /// Return the base58 string representation of the address
    pub fn toString(&self) -> std::string::String {
        std::string::ToString::to_string(self)
    }

    /// Check if a `Address` is on the ed25519 curve.
    #[cfg(feature = "curve25519")]
    pub fn isOnCurve(&self) -> bool {
        self.is_on_curve()
    }

    /// Checks if two `Address`s are equal
    pub fn equals(&self, other: &Address) -> bool {
        self == other
    }

    /// Return the `Uint8Array` representation of the address
    pub fn toBytes(&self) -> std::boxed::Box<[u8]> {
        self.0.clone().into()
    }

    /// Derive a Address from another Address, string seed, and a program id
    #[cfg(feature = "sha2")]
    pub fn createWithSeed(base: &Address, seed: &str, owner: &Address) -> Result<Address, JsValue> {
        Address::create_with_seed(base, seed, owner).map_err(display_to_jsvalue)
    }

    /// Derive a program address from seeds and a program id
    #[cfg(feature = "curve25519")]
    pub fn createProgramAddress(
        seeds: std::boxed::Box<[JsValue]>,
        program_id: &Address,
    ) -> Result<Address, JsValue> {
        let seeds_vec = js_value_to_seeds_vec(&seeds)?;
        let seeds_slice = seeds_vec
            .iter()
            .map(|seed| seed.as_slice())
            .collect::<Vec<_>>();

        Address::create_program_address(seeds_slice.as_slice(), program_id)
            .map_err(display_to_jsvalue)
    }

    /// Find a valid program address
    ///
    /// Returns:
    /// * `[Address, number]` - the program address and bump seed
    #[cfg(feature = "curve25519")]
    pub fn findProgramAddress(
        seeds: std::boxed::Box<[JsValue]>,
        program_id: &Address,
    ) -> Result<JsValue, JsValue> {
        let seeds_vec = js_value_to_seeds_vec(&seeds)?;
        let seeds_slice = seeds_vec
            .iter()
            .map(|seed| seed.as_slice())
            .collect::<Vec<_>>();

        let (address, bump_seed) =
            Address::find_program_address(seeds_slice.as_slice(), program_id);

        let result = Array::new_with_length(2);
        result.set(0, address.into());
        result.set(1, bump_seed.into());
        Ok(result.into())
    }
}
