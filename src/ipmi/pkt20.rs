use super::{AuthType, PayloadType};
use crate::error::Error;
use std::convert::Into;
use std::convert::TryFrom;
use std::convert::TryInto;

const HEADER_LEN_MIN: usize = 12;

// sec 13.6
#[derive(Debug)]
pub struct Header {
    auth_type: u8,
    payload_type: u8,
    oem_iana: Option<u32>,
    oem_payload_id: Option<u16>,
    session_id: u32,
    session_number: u32,
    payload_len: u16,
}

impl From<Header> for Vec<u8> {
    fn from(header: Header) -> Self {
        let mut bytes = vec![header.auth_type, header.payload_type];

        if let Some(oem_iana) = header.oem_iana {
            bytes.extend_from_slice(&oem_iana.to_le_bytes());
        }

        if let Some(oem_payload_id) = header.oem_payload_id {
            bytes.extend_from_slice(&oem_payload_id.to_le_bytes());
        }

        bytes.extend_from_slice(&header.session_id.to_le_bytes());

        bytes.extend_from_slice(&header.session_number.to_le_bytes());

        bytes.extend_from_slice(&header.payload_len.to_le_bytes());

        bytes
    }
}

impl Header {
    pub fn new(
        auth_type: AuthType,
        encrypted: bool,
        authenticated: bool,
        payload_type: PayloadType,
        session_id: u32,
        session_number: u32,
        payload_len: usize,
    ) -> Self {
        let len = u16::try_from(payload_len).unwrap();
        let mut ptype = u8::from(payload_type);

        if encrypted {
            ptype |= 0x80;
        }

        if authenticated {
            ptype |= 0x40;
        }

        Header {
            auth_type: auth_type as u8,
            payload_type: ptype,
            oem_iana: None,       // if payload_type == 0x02
            oem_payload_id: None, // if payload_type == 0x02
            session_id,
            session_number,
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
            payload_type: value[1],
            oem_iana: None,
            oem_payload_id: None,
            session_id: 0,
            session_number: 0,
            payload_len: 0,
        };

        let mut body_start = 18;
        if header.payload_type == 0x02 {
            header.oem_iana = Some(u32::from_le_bytes(value[2..6].try_into().unwrap()));
            header.oem_payload_id = Some(u16::from_le_bytes(value[6..8].try_into().unwrap()));
            header.session_id = u32::from_le_bytes(value[8..12].try_into().unwrap());
            header.session_number = u32::from_le_bytes(value[12..16].try_into().unwrap());
            header.payload_len = u16::from_le_bytes(value[16..18].try_into().unwrap())
        } else {
            header.session_id = u32::from_le_bytes(value[2..6].try_into().unwrap());
            header.session_number = u32::from_le_bytes(value[6..10].try_into().unwrap());
            header.payload_len = u16::from_le_bytes(value[10..12].try_into().unwrap());
            body_start = 12;
        }

        let body_end = body_start + header.payload_len as usize;
        if size < body_end {
            return Err(Error::InvalidPacketLength);
        }

        let body = &value[body_start..body_end];

        let packet = Packet::new(header, body);

        Ok(packet)
    }
}

impl Packet {
    pub fn new(header: Header, payload: impl Into<Vec<u8>>) -> Self {
        Packet {
            header,
            payload: payload.into(),
        }
    }

    pub fn padding(self, _block_size: usize) -> Vec<u8> {
        let mut pkt: Vec<u8> = self.into();
        let pad_size = 4 - ((pkt.len() + 2) % 4);

        // Integrity PAD
        pkt.extend_from_slice(&vec![0xFF; pad_size]);

        // Pad Length
        pkt.push(u8::try_from(pad_size).unwrap());

        // Next Header
        pkt.push(0x07);

        pkt
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
        let header = Header::new(
            AuthType::None,
            false,
            true,
            PayloadType::Sol,
            0x01,
            0x02,
            0x03,
        );
        let bytes: Vec<u8> = header.into();
        assert_eq!(
            vec![0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00],
            bytes
        );
    }

    #[test]
    fn packet_from() {
        let header = Header::new(
            AuthType::None,
            false,
            true,
            PayloadType::Sol,
            0x01,
            0x02,
            0x03,
        );
        let pkt = Packet::new(header, vec![0x01]);
        let bytes: Vec<u8> = pkt.into();
        assert_eq!(
            vec![0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01],
            bytes
        );
    }

    #[test]
    fn packet_padding() {
        let header = Header::new(
            AuthType::None,
            false,
            true,
            PayloadType::Sol,
            0x01,
            0x02,
            0x03,
        );
        let pkt = Packet::new(header, vec![0x01, 0x02, 0x03]);
        let bytes = pkt.padding(0);
        assert_eq!(
            vec![
                0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02,
                0x03, 0xFF, 0xFF, 0xFF, 0x03, 0x07,
            ],
            bytes
        );
    }

    #[test]
    fn packet_payload() {
        let header = Header::new(
            AuthType::None,
            false,
            true,
            PayloadType::Sol,
            0x01,
            0x02,
            0x03,
        );
        let pkt = Packet::new(header, vec![0x01]);
        assert_eq!(&[0x01][..], pkt.payload());
    }
}
