/// Errors returned by [`Phone`](crate::Phone) and [`Call`](crate::Call) methods.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Operation requires an active SIP registration.
    #[error("xphone: not registered")]
    NotRegistered,
    /// No call matching the given identifier was found.
    #[error("xphone: call not found")]
    CallNotFound,
    /// The call or phone is not in a valid state for the requested operation.
    #[error("xphone: invalid state for operation")]
    InvalidState,
    /// No RTP packets received within the configured media timeout.
    #[error("xphone: RTP media timeout")]
    MediaTimeout,
    /// Outbound dial timed out before the remote party answered.
    #[error("xphone: dial timeout exceeded before answer")]
    DialTimeout,
    /// All ports in the configured RTP port range are in use.
    #[error("xphone: RTP port range exhausted")]
    NoRtpPortAvailable,
    /// SIP REGISTER request was rejected, or all retries were exhausted.
    /// `code` is the last SIP status observed across retry attempts (`0` when
    /// no response was received, e.g. transport failure). `reason` carries the
    /// corresponding reason-phrase, or a transport error description when
    /// `code == 0`.
    #[error("{}", format_registration_failed(*code, reason))]
    RegistrationFailed { code: u16, reason: String },
    /// SIP REFER (blind transfer) was rejected or failed.
    #[error("xphone: transfer failed")]
    TransferFailed,
    /// TLS transport was requested but no TLS configuration was provided.
    #[error("xphone: TLS transport requires TLSConfig")]
    TlsConfigRequired,
    /// The supplied character is not a valid DTMF digit (0-9, *, #, A-D).
    #[error("xphone: invalid DTMF digit")]
    InvalidDtmfDigit,
    /// `send_dtmf` called in [`DtmfMode::Rfc4733`](crate::config::DtmfMode)
    /// but RFC 4733 telephone-event (PT 101) was not negotiated with the
    /// remote. Switch to [`DtmfMode::SipInfo`](crate::config::DtmfMode) or
    /// [`DtmfMode::Both`](crate::config::DtmfMode) to fall back to SIP INFO.
    #[error("xphone: RFC 4733 DTMF not negotiated with remote")]
    DtmfNotNegotiated,
    /// Mute was requested but the call is already muted.
    #[error("xphone: already muted")]
    AlreadyMuted,
    /// Unmute was requested but the call is not muted.
    #[error("xphone: not muted")]
    NotMuted,
    /// Video mute was requested but video is already muted.
    #[error("xphone: video already muted")]
    VideoAlreadyMuted,
    /// Video unmute was requested but video is not muted.
    #[error("xphone: video not muted")]
    VideoNotMuted,
    /// Operation requires a video stream but none is active.
    #[error("xphone: no video stream")]
    NoVideoStream,
    /// [`Phone::connect`](crate::Phone) called while already connected.
    #[error("xphone: already connected")]
    AlreadyConnected,
    /// Operation requires an active connection but the phone is disconnected.
    #[error("xphone: not connected")]
    NotConnected,
    /// Configuration is missing the required SIP server host.
    #[error("xphone: Host is required")]
    HostRequired,
    /// SDP parsing or negotiation error with a descriptive message.
    #[error("xphone: {0}")]
    Sdp(String),
    /// Catch-all for errors that do not fit other variants.
    #[error("xphone: {0}")]
    Other(String),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Formats [`Error::RegistrationFailed`] suppressing `code` when it is `0`
/// (pure transport failure) and suppressing `reason` when empty.
fn format_registration_failed(code: u16, reason: &str) -> String {
    match (code, reason.is_empty()) {
        (0, true) => "xphone: registration failed".into(),
        (0, false) => format!("xphone: registration failed: {reason}"),
        (c, true) => format!("xphone: registration failed: {c}"),
        (c, false) => format!("xphone: registration failed: {c} {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert_eq!(Error::NotRegistered.to_string(), "xphone: not registered");
        assert_eq!(
            Error::InvalidState.to_string(),
            "xphone: invalid state for operation"
        );
        assert_eq!(
            Error::InvalidDtmfDigit.to_string(),
            "xphone: invalid DTMF digit"
        );
    }

    #[test]
    fn registration_failed_display_skips_zero_and_empty() {
        let full = Error::RegistrationFailed {
            code: 403,
            reason: "Forbidden".into(),
        };
        assert_eq!(
            full.to_string(),
            "xphone: registration failed: 403 Forbidden"
        );

        let transport = Error::RegistrationFailed {
            code: 0,
            reason: "transport: timeout".into(),
        };
        assert_eq!(
            transport.to_string(),
            "xphone: registration failed: transport: timeout"
        );

        let bare = Error::RegistrationFailed {
            code: 0,
            reason: String::new(),
        };
        assert_eq!(bare.to_string(), "xphone: registration failed");
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<i32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: Result<i32> = Err(Error::NotRegistered);
        assert!(err.is_err());
    }
}
