use super::response::{RakpMessage2, RakpMessage4};
use super::{
    AuthenticationAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm, PrivilegeLevel,
};
use crate::error::Error;
use crate::rmcp;
use hmac::digest::crypto_common::InvalidLength;
use hmac::Mac;
use std::convert::TryFrom;
use std::net::{ToSocketAddrs, UdpSocket};
use uuid::Uuid;

#[derive(Debug)]
pub struct Client<A>
where
    A: ToSocketAddrs,
{
    socket: UdpSocket,
    remote: A,
    sidm: u32,              // Remote Console Session ID
    sidc: u32,              // Managed System Session ID
    rm: u128,               // Remote Console Random Number
    rc: u128,               // Managed System Random Number
    guid: Option<[u8; 16]>, // Managed System GUID
    priv_level: PrivilegeLevel,
    username: String,
    password: String,
    authentication: AuthenticationAlgorithm,
    integrity: IntegrityAlgorithm,
    confidentiality: ConfidentialityAlgorithm,
}

impl<A> Client<A>
where
    A: ToSocketAddrs,
{
    pub fn new(
        socket: UdpSocket,
        remote: A,
        username: &str,
        password: &str,
    ) -> Result<Self, Error> {
        if username.len() > (u8::MAX as usize) {
            return Err(Error::InvalidUsernameLength);
        }

        Ok(Client {
            socket,
            remote,
            sidm: 0,
            sidc: 0,
            rm: u128::from_le_bytes(rand::random::<[u8; 16]>()),
            rc: 0,
            guid: None,
            priv_level: PrivilegeLevel::None,
            username: username.to_string(),
            password: password.to_string(),
            authentication: AuthenticationAlgorithm::None,
            integrity: IntegrityAlgorithm::None,
            confidentiality: ConfidentialityAlgorithm::None,
        })
    }

    pub fn sidm(&self) -> u32 {
        self.sidm
    }

    pub fn set_sidm(&mut self, sidm: u32) {
        self.sidm = sidm;
    }

    pub fn sidc(&self) -> u32 {
        self.sidc
    }

    pub fn set_sidc(&mut self, sidc: u32) {
        self.sidc = sidc;
    }

    pub fn rm(&self) -> u128 {
        self.rm
    }

    pub fn set_rm(&mut self, rm: u128) {
        self.rm = rm;
    }

    pub fn rc(&self) -> u128 {
        self.rc
    }

    pub fn set_rc(&mut self, rc: u128) {
        self.rc = rc;
    }

    pub fn guid(&self) -> Option<Uuid> {
        self.guid.map(Uuid::from_bytes_le)
    }

    pub fn guid_raw(&self) -> Option<[u8; 16]> {
        self.guid
    }

    pub fn set_guid(&mut self, guid: [u8; 16]) {
        self.guid = Some(guid);
    }

    pub fn priv_level(&self) -> PrivilegeLevel {
        self.priv_level
    }

    pub fn set_priv_level(&mut self, priv_level: PrivilegeLevel) {
        self.priv_level = priv_level;
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn authentication(&self) -> AuthenticationAlgorithm {
        self.authentication
    }

    pub fn set_authentication(&mut self, authentication: AuthenticationAlgorithm) {
        self.authentication = authentication;
    }

    pub fn integrity(&self) -> IntegrityAlgorithm {
        self.integrity
    }

    pub fn set_integrity(&mut self, integrity: IntegrityAlgorithm) {
        self.integrity = integrity;
    }

    pub fn confidentiality(&self) -> ConfidentialityAlgorithm {
        self.confidentiality
    }

    pub fn set_confidentiality(&mut self, confidentiality: ConfidentialityAlgorithm) {
        self.confidentiality = confidentiality;
    }

    // sec 13.28.4
    pub fn integrity_data<H: Mac + hmac::digest::KeyInit>(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, InvalidLength> {
        let k1 = self.k1::<H>()?;
        let mut hasher = <H as Mac>::new_from_slice(k1.as_slice())?;
        hasher.update(data);
        let hash = hasher.finalize().into_bytes().to_vec();
        Ok(hash)
    }

    // sec 13.31 Message2
    pub fn check_rakp2<H: Mac + hmac::digest::KeyInit>(
        &self,
        pkt: &RakpMessage2,
    ) -> Result<(), Error> {
        if let Some(auth_code) = pkt.auth_code() {
            let mut data = vec![];
            data.extend_from_slice(&self.sidm.to_le_bytes());
            data.extend_from_slice(&self.sidc.to_le_bytes());
            data.extend_from_slice(&self.rm.to_le_bytes());
            data.extend_from_slice(&pkt.rc().to_le_bytes());
            data.extend_from_slice(&pkt.guid_raw());
            data.push((self.priv_level() as u8) + 0x10);
            data.push(u8::try_from(self.username().len()).unwrap());
            data.extend_from_slice(self.username().as_bytes());

            let integrity = self.hash_kuid::<H>(&data)?;
            for (i, a) in integrity.iter().zip(auth_code.iter()) {
                if i != a {
                    return Err(Error::Integrity);
                }
            }
        }

        Ok(())
    }

    // sec 13.31 Message4
    pub fn check_rakp4<H: Mac + hmac::digest::KeyInit>(
        &self,
        pkt: &RakpMessage4,
    ) -> Result<(), Error> {
        if let Some(auth_code) = pkt.integrity() {
            let mut data = vec![];
            data.extend_from_slice(&self.rm.to_le_bytes());
            data.extend_from_slice(&self.sidc.to_le_bytes());
            data.extend_from_slice(&self.guid_raw().unwrap());

            let integrity = self.hash_sik::<H>(&data)?;
            for (i, a) in integrity.iter().zip(auth_code.iter()) {
                if i != a {
                    return Err(Error::Integrity);
                }
            }
        }

        Ok(())
    }

    // sec 13.31 SIK
    pub fn sik<H: Mac + hmac::digest::KeyInit>(&self) -> Result<Vec<u8>, InvalidLength> {
        let mut sik = vec![];
        sik.extend_from_slice(&self.rm.to_le_bytes());
        sik.extend_from_slice(&self.rc.to_le_bytes());
        sik.push((self.priv_level as u8) + 0x10);
        sik.push(u8::try_from(self.username.len()).unwrap());
        sik.extend_from_slice(self.username.as_bytes());
        // Use Kuid instead of Kg.
        self.hash_kuid::<H>(&sik)
    }

    // sec 13.32 K1
    pub fn k1<H: Mac + hmac::digest::KeyInit>(&self) -> Result<Vec<u8>, InvalidLength> {
        let data = &[
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        self.hash_sik::<H>(data)
    }

    // sec 13.32 K2
    pub fn k2<H: Mac + hmac::digest::KeyInit>(&self) -> Result<Vec<u8>, InvalidLength> {
        let data = &[
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        self.hash_sik::<H>(data)
    }

    pub fn hash_kuid<H: Mac + hmac::digest::KeyInit>(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, InvalidLength> {
        let mut hasher = <H as Mac>::new_from_slice(self.password.as_bytes())?;
        hasher.update(data);
        Ok(hasher.finalize().into_bytes().to_vec())
    }

    pub fn hash_sik<H: Mac + hmac::digest::KeyInit>(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, InvalidLength> {
        let key = self.sik::<H>()?;
        let mut hasher = <H as Mac>::new_from_slice(key.as_slice())?;
        hasher.update(data);
        Ok(hasher.finalize().into_bytes().to_vec())
    }

    pub fn send(&self, data: impl Into<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let res = rmcp::send_ipmi(&self.socket, &self.remote, data)?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Hmac;
    use sha1::Sha1;
    use uuid::uuid;

    type HmacSha1 = Hmac<Sha1>;

    #[test]
    fn integrity_data_ok() {
        let addr = "127.0.0.1:0";
        let socket = UdpSocket::bind(addr).unwrap();
        let mut client = Client::new(socket, addr, "username", "password").unwrap();
        client.set_sidm(1);
        client.set_sidc(2);
        client.set_rm(3);
        client.set_rc(4);
        client.set_guid(*uuid!("11111111-2222-3333-4444-555555555555").as_bytes());
        client.set_priv_level(PrivilegeLevel::Administrator);
        let data: Vec<u8> = client.integrity_data::<HmacSha1>(&[0x01]).unwrap();
        assert_eq!(
            vec![
                0x57, 0x85, 0xAB, 0x6E, 0xF8, 0xAB, 0x4D, 0xE7, 0x6A, 0xDD, 0xC1, 0xEF, 0xF7, 0xFC,
                0xE6, 0x92, 0x27, 0xDA, 0x55, 0x47
            ],
            data
        );
    }

    #[test]
    fn check_rakp2_ok() {
        let addr = "127.0.0.1:0";
        let socket = UdpSocket::bind(addr).unwrap();
        let mut client = Client::new(socket, addr, "username", "password").unwrap();
        client.set_sidm(1);
        client.set_sidc(2);
        client.set_rm(3);
        client.set_priv_level(PrivilegeLevel::Administrator);

        let bytes = vec![
            0x00, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x39, 0x9F,
            0x6A, 0x3F, 0x41, 0x6E, 0x13, 0xBE, 0xE3, 0x49, 0xC3, 0x1E, 0xE8, 0x7C, 0x8D, 0x41,
            0xAA, 0xC8, 0x7E, 0x6E,
        ];
        let pkt = RakpMessage2::parse(&bytes, AuthenticationAlgorithm::HmacSha1).unwrap();

        client.check_rakp2::<HmacSha1>(&pkt).unwrap()
    }

    #[test]
    fn check_rakp4_ok() {
        let addr = "127.0.0.1:0";
        let socket = UdpSocket::bind(addr).unwrap();
        let mut client = Client::new(socket, addr, "username", "password").unwrap();
        client.set_sidm(1);
        client.set_sidc(2);
        client.set_rm(3);
        client.set_rc(4);
        client.set_guid(*uuid!("11111111-2222-3333-4444-555555555555").as_bytes());
        client.set_priv_level(PrivilegeLevel::Administrator);

        let bytes = vec![
            0x00, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x2E, 0xEE, 0xCB, 0x06, 0xC3, 0x85,
            0x5C, 0x42, 0x81, 0xC8, 0x24, 0x38, 0x39, 0xCB, 0x42, 0xD9, 0x5F, 0x42, 0x3B, 0x3B,
        ];
        let pkt = RakpMessage4::parse(&bytes, IntegrityAlgorithm::HmacSha1_96).unwrap();

        client.check_rakp4::<HmacSha1>(&pkt).unwrap()
    }
}
