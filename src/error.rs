/// Errors returned by [`Phone`](crate::Phone) and [`Call`](crate::Call) methods.
#[derive(Debug, thiserror::Error)]
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
    /// SIP REGISTER request was rejected by the server.
    #[error("xphone: registration failed")]
    RegistrationFailed,
    /// SIP REFER (blind transfer) was rejected or failed.
    #[error("xphone: transfer failed")]
    TransferFailed,
    /// TLS transport was requested but no TLS configuration was provided.
    #[error("xphone: TLS transport requires TLSConfig")]
    TlsConfigRequired,
    /// The supplied character is not a valid DTMF digit (0-9, *, #, A-D).
    #[error("xphone: invalid DTMF digit")]
    InvalidDtmfDigit,
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
