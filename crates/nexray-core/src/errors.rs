//! Errors raised by `nexray-core`. Anything user-facing surfaces as a
//! [`SkipReason`](crate::SkipReason); these are the structural-failure
//! variants that callers (CLI, Tauri shell) can't recover from.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("subscription URL must be HTTPS, got: {0}")]
    NotHttps(String),

    #[error("invalid base64 in subscription body")]
    InvalidBase64,
}
