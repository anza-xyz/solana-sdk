use {
    crate::{v1::Message, AccountKeys},
    solana_address::Address,
    std::{borrow::Cow, collections::HashSet},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedMessage<'a> {
    /// Wrapped message.
    pub message: Cow<'a, Message>,
    /// List of boolean with same length as account_keys(), each boolean value indicates if
    /// corresponding account key is writable or not.
    pub is_writable_account_cache: Vec<bool>,
}

impl CachedMessage<'_> {
    pub fn new(message: Message, reserved_account_keys: &HashSet<Address>) -> Self {
        let is_writable_account_cache = message
            .account_keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                message.is_writable_index(i)
                    && !reserved_account_keys.contains(key)
                    && !message.demote_program_id(i)
            })
            .collect::<Vec<_>>();
        Self {
            message: Cow::Owned(message),
            is_writable_account_cache,
        }
    }

    /// Returns true if any account keys are duplicates
    pub fn has_duplicates(&self) -> bool {
        let mut uniq = HashSet::with_capacity(self.account_keys().len());
        self.account_keys().iter().any(|x| !uniq.insert(x))
    }

    pub fn is_key_called_as_program(&self, key_index: usize) -> bool {
        self.message.is_key_called_as_program(key_index)
    }

    /// Inspect all message keys for the bpf upgradeable loader
    pub fn is_upgradeable_loader_present(&self) -> bool {
        self.message.is_upgradeable_loader_present()
    }

    /// Returns the full list of account keys.
    pub fn account_keys(&self) -> AccountKeys<'_> {
        AccountKeys::new(&self.message.account_keys, None)
    }

    pub fn is_writable(&self, index: usize) -> bool {
        *self.is_writable_account_cache.get(index).unwrap_or(&false)
    }

    pub fn demote_program_id(&self, i: usize) -> bool {
        self.is_key_called_as_program(i) && !self.is_upgradeable_loader_present()
    }
}
