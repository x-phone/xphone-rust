//! A SIP telephony library with an event-driven API.
//!
//! Provides registration lifecycle, call state management, media pipeline,
//! and mock types for testing consumer code without a real SIP transport.

pub mod call;
pub mod codec;
pub mod config;
pub mod dialog;
pub mod dtmf;
pub mod error;
pub mod jitter;
pub mod media;
pub mod mock;
pub mod phone;
pub mod registry;
pub mod sdp;
pub mod sip;
pub mod transport;
pub mod types;

// Re-export the primary public API at the crate root.
pub use call::Call;
pub use config::{Config, DialOptions, PhoneBuilder};
pub use error::{Error, Result};
pub use phone::Phone;
pub use sip::conn::TlsConfig;
pub use types::{CallState, Codec, Direction, EndReason, PhoneState};
