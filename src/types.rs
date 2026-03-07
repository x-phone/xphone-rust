use std::fmt;

/// Current state of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallState {
    Idle,
    /// Inbound: INVITE received, not yet accepted.
    Ringing,
    /// Outbound: INVITE sent, no response yet.
    Dialing,
    /// Outbound: 180 received.
    RemoteRinging,
    /// Outbound: 183 received + early media enabled.
    EarlyMedia,
    /// Call established, RTP flowing.
    Active,
    /// Re-INVITE with a=sendonly/inactive.
    OnHold,
    /// Terminal state.
    Ended,
}

impl fmt::Display for CallState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallState::Idle => write!(f, "Idle"),
            CallState::Ringing => write!(f, "Ringing"),
            CallState::Dialing => write!(f, "Dialing"),
            CallState::RemoteRinging => write!(f, "RemoteRinging"),
            CallState::EarlyMedia => write!(f, "EarlyMedia"),
            CallState::Active => write!(f, "Active"),
            CallState::OnHold => write!(f, "OnHold"),
            CallState::Ended => write!(f, "Ended"),
        }
    }
}

/// Registration state of the phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhoneState {
    Disconnected,
    Registering,
    Registered,
    Unregistering,
    RegistrationFailed,
}

impl fmt::Display for PhoneState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneState::Disconnected => write!(f, "Disconnected"),
            PhoneState::Registering => write!(f, "Registering"),
            PhoneState::Registered => write!(f, "Registered"),
            PhoneState::Unregistering => write!(f, "Unregistering"),
            PhoneState::RegistrationFailed => write!(f, "RegistrationFailed"),
        }
    }
}

/// Reason why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndReason {
    /// End() while Active/OnHold.
    Local,
    /// BYE received.
    Remote,
    /// MediaTimeout exceeded.
    Timeout,
    /// Internal or transport error.
    Error,
    /// REFER completed.
    Transfer,
    /// Reject() called.
    Rejected,
    /// End() before 200 OK (outbound).
    Cancelled,
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndReason::Local => write!(f, "Local"),
            EndReason::Remote => write!(f, "Remote"),
            EndReason::Timeout => write!(f, "Timeout"),
            EndReason::Error => write!(f, "Error"),
            EndReason::Transfer => write!(f, "Transfer"),
            EndReason::Rejected => write!(f, "Rejected"),
            EndReason::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Direction of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => write!(f, "Inbound"),
            Direction::Outbound => write!(f, "Outbound"),
        }
    }
}

/// RTP packet header.
#[derive(Debug, Clone)]
pub struct RtpHeader {
    pub version: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

/// RTP packet.
#[derive(Debug, Clone)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

/// Audio codec identified by RTP payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// G.711 mu-law (payload type 0).
    PCMU = 0,
    /// G.711 A-law (payload type 8).
    PCMA = 8,
    /// G.722 (payload type 9).
    G722 = 9,
    /// Opus (payload type 111).
    Opus = 111,
}

impl Codec {
    /// Returns the RTP payload type number.
    pub fn payload_type(self) -> i32 {
        self as i32
    }

    /// Creates a Codec from an RTP payload type number.
    pub fn from_payload_type(pt: i32) -> Option<Codec> {
        match pt {
            0 => Some(Codec::PCMU),
            8 => Some(Codec::PCMA),
            9 => Some(Codec::G722),
            111 => Some(Codec::Opus),
            _ => None,
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Codec::PCMU => write!(f, "PCMU"),
            Codec::PCMA => write!(f, "PCMA"),
            Codec::G722 => write!(f, "G722"),
            Codec::Opus => write!(f, "Opus"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_state_display() {
        assert_eq!(CallState::Idle.to_string(), "Idle");
        assert_eq!(CallState::Active.to_string(), "Active");
        assert_eq!(CallState::Ended.to_string(), "Ended");
    }

    #[test]
    fn phone_state_display() {
        assert_eq!(PhoneState::Disconnected.to_string(), "Disconnected");
        assert_eq!(PhoneState::Registered.to_string(), "Registered");
    }

    #[test]
    fn end_reason_display() {
        assert_eq!(EndReason::Local.to_string(), "Local");
        assert_eq!(EndReason::Remote.to_string(), "Remote");
        assert_eq!(EndReason::Cancelled.to_string(), "Cancelled");
    }

    #[test]
    fn direction_display() {
        assert_eq!(Direction::Inbound.to_string(), "Inbound");
        assert_eq!(Direction::Outbound.to_string(), "Outbound");
    }

    #[test]
    fn codec_payload_type() {
        assert_eq!(Codec::PCMU.payload_type(), 0);
        assert_eq!(Codec::PCMA.payload_type(), 8);
        assert_eq!(Codec::G722.payload_type(), 9);
        assert_eq!(Codec::Opus.payload_type(), 111);
    }

    #[test]
    fn codec_from_payload_type() {
        assert_eq!(Codec::from_payload_type(0), Some(Codec::PCMU));
        assert_eq!(Codec::from_payload_type(8), Some(Codec::PCMA));
        assert_eq!(Codec::from_payload_type(9), Some(Codec::G722));
        assert_eq!(Codec::from_payload_type(111), Some(Codec::Opus));
        assert_eq!(Codec::from_payload_type(99), None);
    }

    #[test]
    fn codec_display() {
        assert_eq!(Codec::PCMU.to_string(), "PCMU");
        assert_eq!(Codec::G722.to_string(), "G722");
    }

    #[test]
    fn enums_are_copy_clone_eq() {
        let s1 = CallState::Active;
        let s2 = s1;
        assert_eq!(s1, s2);

        let d1 = Direction::Inbound;
        let d2 = d1;
        assert_eq!(d1, d2);
    }
}
