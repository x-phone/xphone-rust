//! A SIP telephony library with an event-driven API.
//!
//! Provides registration lifecycle, call state management, media pipeline,
//! and mock types for testing consumer code without a real SIP transport.

pub mod call;
pub(crate) mod callback_pool;
pub mod codec;
pub mod config;
pub mod dialog;
pub mod dialog_info;
pub mod dtmf;
pub mod error;
pub mod ice;
pub mod jitter;
pub mod media;
pub mod mock;
pub mod mwi;
pub mod phone;
pub mod registry;
pub mod rtcp;
pub mod sdp;
pub mod sip;
pub mod srtp;
pub mod stun;
pub mod subscription;
pub mod transport;
pub mod turn;
pub mod types;
pub mod video;

// Re-export the primary public API at the crate root.
pub use call::Call;
pub use config::{Config, DialOptions, DtmfMode, PhoneBuilder};
pub use error::{Error, Result};
pub use phone::Phone;
pub use sip::conn::TlsConfig;
pub use subscription::SubId;
pub use types::{
    CallState, Codec, Direction, EndReason, ExtensionState, ExtensionStatus, NotifyEvent,
    PhoneState, SipMessage, SubState, VideoCodec, VideoFrame, VoicemailStatus,
};
