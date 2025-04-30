#![deprecated(since = "2.3.0", note = "Use solana_nonce instead")]

pub use solana_nonce::{state::State, NONCED_TX_MARKER_IX_INDEX};
pub mod state {
    pub use solana_nonce::{
        state::{Data, DurableNonce, State},
        versions::{AuthorizeNonceError, Versions},
    };
}
