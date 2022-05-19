use super::error::Error;
use std::convert::Into;
use std::net::{ToSocketAddrs, UdpSocket};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Version {
    V1 = 0x06,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageClass {
    Ipmi = 0x07,
}

// sec 13.6
#[derive(Debug)]
pub struct Header {
    version: u8,
    seq_number: u8,
    class: u8,
}

impl From<Header> for Vec<u8> {
    fn from(header: Header) -> Vec<u8> {
        vec![header.version, 0x00, header.seq_number, header.class]
    }
}

impl Header {
    pub fn ipmi() -> Self {
        Header {
            version: Version::V1 as u8,
            seq_number: 0xFF,
            class: MessageClass::Ipmi as u8,
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    header: Header,
    data: Vec<u8>,
}

impl From<Packet> for Vec<u8> {
    fn from(pkt: Packet) -> Vec<u8> {
        let mut p: Vec<u8> = pkt.header.into();
        p.extend_from_slice(&pkt.data);
        p
    }
}

impl Packet {
    pub fn ipmi(data: impl Into<Vec<u8>>) -> Self {
        Packet {
            header: Header::ipmi(),
            data: data.into(),
        }
    }
}

pub fn send_ipmi(
    socket: &UdpSocket,
    remote: impl ToSocketAddrs,
    data: impl Into<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let pkt = Packet::ipmi(data);

    let bytes: Vec<u8> = pkt.into();

    socket.send_to(&bytes, remote).map_err(Error::SendPacket)?;

    let mut buffer = [0u8; 1024];
    let size = socket.recv(&mut buffer).map_err(Error::RecvPacket)?;

    // RMCP Header を除いて返却する。
    Ok(buffer[4..size].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_ipmi() {
        let header = Header::ipmi();
        let bytes: Vec<u8> = header.into();
        assert_eq!(vec![0x06, 0x00, 0xFF, 0x07], bytes);
    }

    #[test]
    fn packet_ipmi() {
        let pkt = Packet::ipmi([0x01]);
        let bytes: Vec<u8> = pkt.into();
        assert_eq!(vec![0x06, 0x00, 0xFF, 0x07, 0x01], bytes);
    }
}
