//! mask — a PII pseudonymization gateway for LLM APIs.
//!
//! Real names never reach the model, and mask guarantees the way back.
//! This crate contains the whole tool: the detection/replacement/restore
//! pipeline, the OpenAI- and Anthropic-compatible gateway, and the error-free
//! shell entrance used by the `mask` binary.

pub mod cli;
pub mod detect;
pub mod gateway;
pub mod normalize;
pub mod replace;
pub mod restore;
pub mod session;
pub mod types;

pub use session::Session;
pub use types::{DetectionResult, Entity, EntityType, Source};

/// Install the process-wide rustls crypto provider exactly once.
///
/// The gateway builds its own TLS stack (ring) so the binary stays
/// self-contained on Windows/macOS/Linux with no OpenSSL or cmake dependency.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
