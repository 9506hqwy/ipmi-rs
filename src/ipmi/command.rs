use super::response::{RakpMessage2, RakpMessage4, Response, RmcppOpenResponse};
use super::{
    pkt15, pkt20, request, AuthType, AuthenticationAlgorithm, ChassisPowerState, Client,
    ConfidentialityAlgorithm, IntegrityAlgorithm, PayloadType, PrivilegeLevel,
};
use crate::error::Error;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Hmac;
use rand;
use sha1::Sha1;
use std::convert::TryFrom;
use std::net::ToSocketAddrs;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

pub fn get_channel_authentication_cap<A: ToSocketAddrs>(
    client: &Client<A>,
) -> Result<Response, Error> {
    let req = request::get_channel_authentication_cap(PrivilegeLevel::Administrator);

    let header = pkt15::Header::new(AuthType::None, 0, 0, req.pkt_len());

    let packet = pkt15::Packet::new(header, req);

    let res = client.send(packet)?;

    let packet = pkt15::Packet::try_from(res.as_slice())?;

    let pkt = Response::parse(packet.payload())?;

    Ok(pkt)
}

pub fn open_rmcpp_session<A: ToSocketAddrs>(
    client: &mut Client<A>,
    remote_id: u32,
    authentication: AuthenticationAlgorithm,
    integrity: IntegrityAlgorithm,
    confidentiality: ConfidentialityAlgorithm,
) -> Result<RmcppOpenResponse, Error> {
    let req = request::open_rmcpp_session(remote_id, authentication, integrity, confidentiality);

    let header = pkt20::Header::new(
        AuthType::Format,
        false,
        false,
        PayloadType::RmcpOpenRequest,
        0,
        0,
        req.pkt_len(),
    );

    let packet = pkt20::Packet::new(header, req);

    let res = client.send(packet)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let pkt = RmcppOpenResponse::parse(pkt.payload())?;
    client.set_priv_level(pkt.priv_level());
    client.set_sidm(pkt.remote_id());
    client.set_sidc(pkt.session_id());
    client.set_authentication(pkt.authentication());
    client.set_integrity(pkt.integrity());
    client.set_confidentiality(pkt.confidentiality());

    Ok(pkt)
}

pub fn rakp_message_1<A: ToSocketAddrs>(client: &mut Client<A>) -> Result<RakpMessage2, Error> {
    let msg = request::RakpMessage1::new(
        client.sidc(),
        client.rm(),
        client.priv_level(),
        client.username(),
    );

    let header = pkt20::Header::new(
        AuthType::Format,
        false,
        false,
        PayloadType::RakpMessage1,
        0,
        0,
        msg.pkt_len(),
    );

    let packet = pkt20::Packet::new(header, msg);

    let res = client.send(packet)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let rakp2 = RakpMessage2::parse(pkt.payload(), client.authentication())?;
    client.check_rakp2::<HmacSha1>(&rakp2)?;

    client.set_rc(rakp2.rc());
    client.set_guid(rakp2.guid_raw());

    Ok(rakp2)
}

pub fn rakp_message_3<A: ToSocketAddrs>(client: &Client<A>) -> Result<RakpMessage4, Error> {
    let auth_code = if client.integrity() != IntegrityAlgorithm::None {
        // sec 13.31 Message3
        let mut key = vec![];
        key.extend_from_slice(&client.rc().to_le_bytes());
        key.extend_from_slice(&client.sidm().to_le_bytes());
        key.push((client.priv_level() as u8) + 0x10);
        key.push(u8::try_from(client.username().len()).unwrap());
        key.extend_from_slice(client.username().as_bytes());

        Some(client.hash_kuid::<HmacSha1>(key.as_slice())?)
    } else {
        None
    };

    let msg = request::RakpMessage3::new(0, client.sidc(), auth_code.as_deref());

    let header = pkt20::Header::new(
        AuthType::Format,
        false,
        false,
        PayloadType::RakpMessage3,
        0,
        0,
        msg.pkt_len(),
    );

    let packet = pkt20::Packet::new(header, msg);

    let res = client.send(packet)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let rakp4 = RakpMessage4::parse(pkt.payload(), client.integrity())?;
    client.check_rakp4::<HmacSha1>(&rakp4)?;

    Ok(rakp4)
}

pub fn set_privilege_level<A: ToSocketAddrs>(
    client: &Client<A>,
    seq_number: u32,
) -> Result<Response, Error> {
    let req = request::set_privilege_level(PrivilegeLevel::Administrator);
    let msg = req.padding(client.confidentiality().key_len());

    let cipher = encrypt_payload(client, msg)?;

    let header = pkt20::Header::new(
        AuthType::Format,
        true,
        true,
        PayloadType::Ipmi,
        client.sidc(),
        seq_number,
        cipher.len(),
    );

    let packet = pkt20::Packet::new(header, cipher);

    let mut pkt = packet.padding(client.integrity().key_len());

    let auth_code = client.integrity_data::<HmacSha1>(&pkt)?;
    pkt.extend_from_slice(&auth_code[..client.integrity().key_len()]);

    let res = client.send(pkt)?;
    check_integrity(client, &res)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let response = decrypt_payload(client, pkt.payload())?;

    Ok(response)
}

pub fn get_chassis_status<A: ToSocketAddrs>(
    client: &Client<A>,
    seq_number: u32,
) -> Result<Response, Error> {
    let req = request::get_chassis_status();
    let msg = req.padding(client.confidentiality().key_len());

    let cipher = encrypt_payload(client, msg)?;

    let header = pkt20::Header::new(
        AuthType::Format,
        true,
        true,
        PayloadType::Ipmi,
        client.sidc(),
        seq_number,
        cipher.len(),
    );

    let packet = pkt20::Packet::new(header, cipher);

    let mut pkt = packet.padding(client.integrity().key_len());

    let auth_code = client.integrity_data::<HmacSha1>(&pkt)?;
    pkt.extend_from_slice(&auth_code[..client.integrity().key_len()]);

    let res = client.send(pkt)?;
    check_integrity(client, &res)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let response = decrypt_payload(client, pkt.payload())?;

    Ok(response)
}

pub fn control_chassis<A: ToSocketAddrs>(
    client: &Client<A>,
    seq_number: u32,
    state: ChassisPowerState,
) -> Result<Response, Error> {
    let req = request::control_chassis(state);
    let msg = req.padding(client.confidentiality().key_len());

    let cipher = encrypt_payload(client, msg)?;

    let header = pkt20::Header::new(
        AuthType::Format,
        true,
        true,
        PayloadType::Ipmi,
        client.sidc(),
        seq_number,
        cipher.len(),
    );

    let packet = pkt20::Packet::new(header, cipher);

    let mut pkt = packet.padding(client.integrity().key_len());

    let auth_code = client.integrity_data::<HmacSha1>(&pkt)?;
    pkt.extend_from_slice(&auth_code[..client.integrity().key_len()]);

    let res = client.send(pkt)?;
    check_integrity(client, &res)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let response = decrypt_payload(client, pkt.payload())?;

    Ok(response)
}

pub fn close_session<A: ToSocketAddrs>(
    client: &Client<A>,
    seq_number: u32,
) -> Result<Response, Error> {
    let req = request::close_session(client.sidc());
    let msg = req.padding(client.confidentiality().key_len());

    let cipher = encrypt_payload(client, msg)?;

    let header = pkt20::Header::new(
        AuthType::Format,
        true,
        true,
        PayloadType::Ipmi,
        client.sidc(),
        seq_number,
        cipher.len(),
    );

    let packet = pkt20::Packet::new(header, cipher);

    let mut pkt = packet.padding(client.integrity().key_len());

    let auth_code = client.integrity_data::<HmacSha1>(&pkt)?;
    pkt.extend_from_slice(&auth_code[..client.integrity().key_len()]);

    let res = client.send(pkt)?;
    check_integrity(client, &res)?;

    let pkt = pkt20::Packet::try_from(res.as_slice())?;

    let response = decrypt_payload(client, pkt.payload())?;

    Ok(response)
}

fn check_integrity<A: ToSocketAddrs>(client: &Client<A>, response: &[u8]) -> Result<(), Error> {
    let size = response.len();
    let integrity_start = size - client.integrity().key_len();
    let data = &response[integrity_start..];
    let auth_code = client.integrity_data::<HmacSha1>(&response[..integrity_start])?;
    for (i, a) in data.iter().zip(auth_code.iter()) {
        if i != a {
            return Err(Error::Integrity);
        }
    }

    Ok(())
}

// sec 13.29
fn decrypt_payload<A: ToSocketAddrs>(
    client: &Client<A>,
    payload: &[u8],
) -> Result<Response, Error> {
    if payload.len() < 32 {
        return Err(Error::InvalidPacketLength);
    }

    let k2 = client.k2::<HmacSha1>()?;
    let decryptor = Aes128CbcDec::new(k2[..16].into(), payload[..16].into());
    let mut cipher = payload[16..].to_vec();
    let plain = decryptor.decrypt_padded_mut::<NoPadding>(&mut cipher)?;
    let pad_size = *plain.last().unwrap() as usize;
    let payload_end = plain.len() - pad_size - 1;
    let res = Response::parse(&plain[..payload_end])?;
    Ok(res)
}

// sec 13.29
fn encrypt_payload<A: ToSocketAddrs>(
    client: &Client<A>,
    mut payload: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let k2 = client.k2::<HmacSha1>()?;
    let iv = rand::random::<[u8; 16]>(); // TODO: sec 13.34
    let cipher = Aes128CbcEnc::new(k2[..16].into(), &iv.into());
    let len = payload.len();
    let cipher = cipher.encrypt_padded_mut::<NoPadding>(&mut payload, len)?;
    let mut padded = iv.to_vec();
    padded.extend_from_slice(cipher);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use uuid::uuid;

    #[test]
    fn enc_dec_no_padding() {
        let addr = "127.0.0.1:0";
        let socket = UdpSocket::bind(addr).unwrap();
        let mut client = Client::new(socket, addr, "username", "password").unwrap();
        client.set_sidm(1);
        client.set_sidc(2);
        client.set_rm(3);
        client.set_rc(4);
        client.set_guid(*uuid!("11111111-2222-3333-4444-555555555555").as_bytes());
        client.set_priv_level(PrivilegeLevel::Administrator);

        let plain = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x00,
        ];
        let cipher = encrypt_payload(&client, plain.clone()).unwrap();
        let pkt = decrypt_payload(&client, &cipher).unwrap();
        assert_eq!(
            &[0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03][..],
            pkt.data().unwrap()
        );
    }

    #[test]
    fn enc_dec_with_padding() {
        let addr = "127.0.0.1:0";
        let socket = UdpSocket::bind(addr).unwrap();
        let mut client = Client::new(socket, addr, "username", "password").unwrap();
        client.set_sidm(1);
        client.set_sidc(2);
        client.set_rm(3);
        client.set_rc(4);
        client.set_guid(*uuid!("11111111-2222-3333-4444-555555555555").as_bytes());
        client.set_priv_level(PrivilegeLevel::Administrator);

        let plain = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x01,
            0x02, 0x02,
        ];
        let cipher = encrypt_payload(&client, plain.clone()).unwrap();
        let pkt = decrypt_payload(&client, &cipher).unwrap();
        assert_eq!(&[0x07, 0x08, 0x09, 0x00, 0x01][..], pkt.data().unwrap());
    }
}
