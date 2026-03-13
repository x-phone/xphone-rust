//! SIP trunk host server — accept and place calls directly with trusted SIP peers.
//!
//! Provides [`Server`] as an alternative to [`Phone`](crate::phone::Phone) for deployments
//! that receive SIP INVITEs directly from trunk providers (Twilio, Telnyx) or PBXes
//! without requiring SIP registration.
//!
//! Both modes produce the same [`Call`](crate::call::Call) object — the downstream API
//! (accept, hangup, DTMF, media, PCM access) is identical.

pub mod auth;
pub mod config;
pub mod dialog;
pub mod server;
pub(crate) mod util;
