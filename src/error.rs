/// Errors returned by Phone and Call methods.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("xphone: not registered")]
    NotRegistered,
    #[error("xphone: call not found")]
    CallNotFound,
    #[error("xphone: invalid state for operation")]
    InvalidState,
    #[error("xphone: RTP media timeout")]
    MediaTimeout,
    #[error("xphone: dial timeout exceeded before answer")]
    DialTimeout,
    #[error("xphone: RTP port range exhausted")]
    NoRtpPortAvailable,
    #[error("xphone: registration failed")]
    RegistrationFailed,
    #[error("xphone: transfer failed")]
    TransferFailed,
    #[error("xphone: TLS transport requires TLSConfig")]
    TlsConfigRequired,
    #[error("xphone: invalid DTMF digit")]
    InvalidDtmfDigit,
    #[error("xphone: already muted")]
    AlreadyMuted,
    #[error("xphone: not muted")]
    NotMuted,
    #[error("xphone: already connected")]
    AlreadyConnected,
    #[error("xphone: not connected")]
    NotConnected,
    #[error("xphone: Host is required")]
    HostRequired,
    #[error("xphone: {0}")]
    Sdp(String),
    #[error("xphone: {0}")]
    Other(String),
}

/// Convenience alias.
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
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = Err(Error::NotRegistered);
        assert!(err.is_err());
    }
}
