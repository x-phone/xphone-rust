use crate::error::Error;
use crate::types::{RtpHeader, RtpPacket};

/// RTP payload type for DTMF events (RFC 4733).
pub const DTMF_PAYLOAD_TYPE: u8 = 101;

/// A decoded DTMF event from an RTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfEvent {
    pub digit: String,
    pub duration: u16,
    pub end: bool,
    pub volume: u8,
}

/// Returns the RFC 4733 event code for a digit string.
/// Returns `None` if the digit is invalid.
pub fn digit_to_code(digit: &str) -> Option<u8> {
    match digit {
        "0" => Some(0),
        "1" => Some(1),
        "2" => Some(2),
        "3" => Some(3),
        "4" => Some(4),
        "5" => Some(5),
        "6" => Some(6),
        "7" => Some(7),
        "8" => Some(8),
        "9" => Some(9),
        "*" => Some(10),
        "#" => Some(11),
        "A" => Some(12),
        "B" => Some(13),
        "C" => Some(14),
        "D" => Some(15),
        _ => None,
    }
}

/// Returns the digit string for an RFC 4733 event code.
/// Returns `None` if the code is unknown.
pub fn code_to_digit(code: u8) -> Option<&'static str> {
    match code {
        0 => Some("0"),
        1 => Some("1"),
        2 => Some("2"),
        3 => Some("3"),
        4 => Some("4"),
        5 => Some("5"),
        6 => Some("6"),
        7 => Some("7"),
        8 => Some("8"),
        9 => Some("9"),
        10 => Some("*"),
        11 => Some("#"),
        12 => Some("A"),
        13 => Some("B"),
        14 => Some("C"),
        15 => Some("D"),
        _ => None,
    }
}

/// Encodes a DTMF digit into a sequence of RTP packets (RFC 4733).
pub fn encode_dtmf(
    digit: &str,
    ts: u32,
    seq: u16,
    ssrc: u32,
) -> crate::error::Result<Vec<RtpPacket>> {
    let code = digit_to_code(digit).ok_or(Error::InvalidDtmfDigit)?;

    const VOLUME: u8 = 10;
    let durations: [u16; 3] = [160, 320, 320];
    let mut pkts = Vec::with_capacity(3);

    for (i, &dur) in durations.iter().enumerate() {
        let end_bit: u8 = if i == 2 { 0x80 } else { 0 };
        let mut payload = vec![0u8; 4];
        payload[0] = code;
        payload[1] = end_bit | VOLUME;
        payload[2] = (dur >> 8) as u8;
        payload[3] = dur as u8;

        pkts.push(RtpPacket {
            header: RtpHeader {
                version: 2,
                marker: i == 0,
                payload_type: DTMF_PAYLOAD_TYPE,
                sequence_number: seq.wrapping_add(i as u16),
                timestamp: ts,
                ssrc,
            },
            payload,
        });
    }

    Ok(pkts)
}

/// Decodes a DTMF event from an RTP payload.
/// Returns `None` if the payload is less than 4 bytes or the code is unknown.
pub fn decode_dtmf(payload: &[u8]) -> Option<DtmfEvent> {
    if payload.len() < 4 {
        return None;
    }
    let code = payload[0];
    let digit = code_to_digit(code)?;
    Some(DtmfEvent {
        digit: digit.to_string(),
        end: payload[1] & 0x80 != 0,
        volume: payload[1] & 0x3F,
        duration: u16::from_be_bytes([payload[2], payload[3]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_code_valid_digits() {
        let cases = [
            ("0", 0),
            ("1", 1),
            ("2", 2),
            ("3", 3),
            ("4", 4),
            ("5", 5),
            ("6", 6),
            ("7", 7),
            ("8", 8),
            ("9", 9),
            ("*", 10),
            ("#", 11),
            ("A", 12),
            ("B", 13),
            ("C", 14),
            ("D", 15),
        ];
        for (digit, expected) in cases {
            assert_eq!(digit_to_code(digit), Some(expected), "digit={digit}");
        }
    }

    #[test]
    fn digit_code_invalid_returns_none() {
        assert_eq!(digit_to_code("X"), None);
        assert_eq!(digit_to_code(""), None);
        assert_eq!(digit_to_code("10"), None);
    }

    #[test]
    fn code_digit_round_trip() {
        let digits = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "#", "A", "B", "C", "D",
        ];
        for digit in digits {
            let code = digit_to_code(digit).unwrap();
            assert_eq!(
                code_to_digit(code),
                Some(digit),
                "round-trip failed for digit {digit}"
            );
        }
    }

    #[test]
    fn decode_valid_payload() {
        // RFC 4733 payload: event=5, E=0, volume=10, duration=1000
        let payload = [5u8, 0x0A, 0x03, 0xE8];
        let ev = decode_dtmf(&payload).unwrap();
        assert_eq!(ev.digit, "5");
        assert_eq!(ev.volume, 10);
        assert_eq!(ev.duration, 1000);
        assert!(!ev.end);
    }

    #[test]
    fn decode_end_bit_set() {
        let payload = [5u8, 0x8A, 0x03, 0xE8];
        let ev = decode_dtmf(&payload).unwrap();
        assert!(ev.end);
    }

    #[test]
    fn decode_short_payload_returns_none() {
        assert!(decode_dtmf(&[1, 2, 3]).is_none());
        assert!(decode_dtmf(&[]).is_none());
    }

    #[test]
    fn encode_produces_packets() {
        let pkts = encode_dtmf("5", 0, 0, 0x12345678).unwrap();
        assert!(pkts.len() >= 3);
    }

    #[test]
    fn encode_all_packets_have_pt101() {
        let pkts = encode_dtmf("5", 0, 0, 0x12345678).unwrap();
        for (i, pkt) in pkts.iter().enumerate() {
            assert_eq!(pkt.header.payload_type, DTMF_PAYLOAD_TYPE, "packet {i}");
        }
    }

    #[test]
    fn encode_last_packet_has_end_bit() {
        let pkts = encode_dtmf("5", 0, 0, 0x12345678).unwrap();
        assert!(!pkts.is_empty());
        let last = pkts.last().unwrap();
        assert!(last.payload.len() >= 4);
        assert!(
            last.payload[1] & 0x80 != 0,
            "last packet should have E bit set"
        );
    }

    #[test]
    fn encode_invalid_digit_returns_error() {
        let result = encode_dtmf("X", 0, 0, 0x12345678);
        assert!(result.is_err());
    }

    #[test]
    fn encode_first_packet_has_marker() {
        let pkts = encode_dtmf("5", 0, 0, 0x12345678).unwrap();
        assert!(pkts[0].header.marker);
        assert!(!pkts[1].header.marker);
    }

    #[test]
    fn encode_sequential_sequence_numbers() {
        let pkts = encode_dtmf("5", 0, 100, 0x12345678).unwrap();
        assert_eq!(pkts[0].header.sequence_number, 100);
        assert_eq!(pkts[1].header.sequence_number, 101);
        assert_eq!(pkts[2].header.sequence_number, 102);
    }
}
