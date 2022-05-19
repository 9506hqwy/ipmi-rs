use super::AuthType;
use crate::error::Error;
use std::convert::Into;
use std::convert::TryFrom;
use std::convert::TryInto;

const HEADER_LEN_MIN: usize = 10;

// sec 13.6
#[derive(Debug)]
pub struct Header {
    auth_type: u8,
    session_number: u32,
    session_id: u32,
    auth_code: Option<u128>,
    payload_len: u8,
}

impl From<Header> for Vec<u8> {
    fn from(header: Header) -> Self {
        let mut bytes = vec![header.auth_type];

        bytes.extend_from_slice(&header.session_number.to_le_bytes());

        bytes.extend_from_slice(&header.session_id.to_le_bytes());

        if let Some(auth_code) = header.auth_code {
            bytes.extend_from_slice(&auth_code.to_le_bytes());
        }

        bytes.extend_from_slice(&header.payload_len.to_le_bytes());

        bytes
    }
}

impl Header {
    pub fn new(
        auth_type: AuthType,
        session_number: u32,
        session_id: u32,
        payload_len: usize,
    ) -> Self {
        let len = u8::try_from(payload_len).unwrap();
        Header {
            auth_type: auth_type as u8,
            session_number,
            session_id,
            auth_code: None,
            payload_len: len,
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    header: Header,
    payload: Vec<u8>,
}

impl From<Packet> for Vec<u8> {
    fn from(pkt: Packet) -> Self {
        let mut bytes = vec![];

        let header: Vec<u8> = pkt.header.into();
        bytes.extend_from_slice(&header);

        bytes.extend_from_slice(&pkt.payload);

        bytes
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let size = value.len();
        if size < HEADER_LEN_MIN {
            return Err(Error::InvalidPacketLength);
        }

        let mut header = Header {
            auth_type: value[0],
            session_number: u32::from_le_bytes(value[1..5].try_into().unwrap()),
            session_id: u32::from_le_bytes(value[5..9].try_into().unwrap()),
            auth_code: None,
            payload_len: 0,
        };

        let mut payload_start = 10;
        if header.auth_type == (AuthType::None as u8) {
            header.payload_len = value[9];
        } else {
            payload_start = 26;
            header.auth_code = Some(u128::from_le_bytes(value[9..25].try_into().unwrap()));
            header.payload_len = value[25];
        }

        let payload_end = payload_start + header.payload_len as usize;
        if size < payload_end {
            return Err(Error::InvalidPacketLength);
        }

        Ok(Packet::new(header, &value[payload_start..payload_end]))
    }
}

impl Packet {
    pub fn new(header: Header, payload: impl Into<Vec<u8>>) -> Self {
        Packet {
            header,
            payload: payload.into(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_from() {
        let header = Header::new(AuthType::None, 1, 2, 3);
        let bytes: Vec<u8> = header.into();
        assert_eq!(
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03],
            bytes
        );
    }

    #[test]
    fn packet_from() {
        let header = Header::new(AuthType::None, 1, 2, 3);
        let pkt = Packet::new(header, vec![0x01]);
        let bytes: Vec<u8> = pkt.into();
        assert_eq!(
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01],
            bytes
        );
    }

    #[test]
    fn packet_playload() {
        let header = Header::new(AuthType::None, 1, 2, 3);
        let pkt = Packet::new(header, vec![0x01]);
        assert_eq!(&[0x01][..], pkt.payload());
    }

    #[test]
    fn packet_try_from_invali_packet_length() {
        let bytes = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        match Packet::try_from(bytes.as_slice()) {
            Err(Error::InvalidPacketLength) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn packet_try_from_ok() {
        let bytes = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03,
        ];
        let pkt = Packet::try_from(bytes.as_slice()).unwrap();
        assert_eq!(0, pkt.header.auth_type);
        assert_eq!(1, pkt.header.session_number);
        assert_eq!(2, pkt.header.session_id);
        assert_eq!(None, pkt.header.auth_code);
        assert_eq!(3, pkt.header.payload_len);
        assert_eq!(vec![0x01, 0x02, 0x03], pkt.payload);
    }
}
