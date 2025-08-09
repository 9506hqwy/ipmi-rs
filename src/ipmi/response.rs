use super::{
    AuthenticationAlgorithm, CompletionCode, ConfidentialityAlgorithm, IntegrityAlgorithm,
    PrivilegeLevel,
};
use crate::error::Error;
use std::convert::TryInto;
use uuid::Uuid;

// sec 13.8
#[derive(Debug)]
pub struct Response {
    rq_addr: u8,
    netfn: u8,
    rs_addr: u8,
    rq_seq: u8,
    cmd: u8,
    code: CompletionCode,
    data: Option<Vec<u8>>,
}

impl Response {
    pub fn rq_addr(&self) -> u8 {
        self.rq_addr
    }

    pub fn netfn(&self) -> u8 {
        self.netfn
    }

    pub fn rs_addr(&self) -> u8 {
        self.rs_addr
    }

    pub fn rq_seq(&self) -> u8 {
        self.rq_seq
    }

    pub fn cmd(&self) -> u8 {
        self.cmd
    }

    pub fn code(&self) -> CompletionCode {
        self.code
    }

    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn parse(response: &[u8]) -> Result<Response, Error> {
        let size = response.len();
        if size < 8 {
            return Err(Error::InvalidPacketLength);
        }

        let mut res = Response {
            rq_addr: response[0],
            netfn: response[1],
            rs_addr: response[3],
            rq_seq: response[4],
            cmd: response[5],
            code: CompletionCode::from(response[6]),
            data: None,
        };

        if res.code != CompletionCode::Completed {
            return Err(Error::IpmiCommand(res.code));
        }

        if size > 8 {
            // remove last checksum (1 bytes).
            res.data = Some(response[7..(size - 1)].to_vec());
        }

        Ok(res)
    }
}

// sec 13.18
#[derive(Debug)]
pub struct RmcppOpenResponse {
    message_tag: u8,
    status_code: u8,
    priv_level: u8,
    remote_id: u32,
    session_id: u32,
    auth_type: Vec<u8>,
    integrity: Vec<u8>,
    confidentiality: Vec<u8>,
}

impl RmcppOpenResponse {
    pub fn message_tag(&self) -> u8 {
        self.message_tag
    }

    pub fn status_code(&self) -> u8 {
        self.status_code
    }

    pub fn priv_level(&self) -> PrivilegeLevel {
        PrivilegeLevel::from(self.priv_level)
    }

    pub fn remote_id(&self) -> u32 {
        self.remote_id
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn authentication(&self) -> AuthenticationAlgorithm {
        AuthenticationAlgorithm::from(self.auth_type[4] & 0x3F)
    }

    pub fn integrity(&self) -> IntegrityAlgorithm {
        IntegrityAlgorithm::from(self.integrity[4] & 0x3F)
    }

    pub fn confidentiality(&self) -> ConfidentialityAlgorithm {
        ConfidentialityAlgorithm::from(self.confidentiality[4] & 0x3F)
    }

    pub fn parse(response: &[u8]) -> Result<RmcppOpenResponse, Error> {
        let size = response.len();
        if size < 36 {
            return Err(Error::InvalidPacketLength);
        }

        let res = RmcppOpenResponse {
            message_tag: response[0],
            status_code: response[1],
            priv_level: response[2],
            remote_id: u32::from_le_bytes(response[4..8].try_into().unwrap()),
            session_id: u32::from_le_bytes(response[8..12].try_into().unwrap()),
            auth_type: response[12..20].to_vec(),
            integrity: response[20..28].to_vec(),
            confidentiality: response[28..36].to_vec(),
        };

        if res.status_code != 0x00 {
            return Err(Error::RmcppCommand(res.status_code));
        }

        Ok(res)
    }
}

//sec 13.21
#[derive(Debug)]
pub struct RakpMessage2 {
    message_tag: u8,
    status_code: u8,
    remote_id: u32,
    rc: u128,
    guid: [u8; 16],
    auth_code: Option<Vec<u8>>,
}

impl RakpMessage2 {
    pub fn message_tag(&self) -> u8 {
        self.message_tag
    }

    pub fn status_code(&self) -> u8 {
        self.status_code
    }

    pub fn remote_id(&self) -> u32 {
        self.remote_id
    }

    pub fn rc(&self) -> u128 {
        self.rc
    }

    pub fn guid(&self) -> Uuid {
        Uuid::from_bytes_le(self.guid)
    }

    pub fn guid_raw(&self) -> [u8; 16] {
        self.guid
    }

    pub fn auth_code(&self) -> Option<&[u8]> {
        self.auth_code.as_deref()
    }

    pub fn parse(
        response: &[u8],
        authentication: AuthenticationAlgorithm,
    ) -> Result<RakpMessage2, Error> {
        let auth_end = 40 + authentication.key_len();

        let size = response.len();
        if size < auth_end {
            return Err(Error::InvalidPacketLength);
        }

        let mut res = RakpMessage2 {
            message_tag: response[0],
            status_code: response[1],
            remote_id: u32::from_le_bytes(response[4..8].try_into().unwrap()),
            rc: u128::from_le_bytes(response[8..24].try_into().unwrap()),
            guid: response[24..40].try_into().unwrap(),
            auth_code: None,
        };

        if 40 < size {
            res.auth_code = Some(response[40..auth_end].to_vec());
        }

        if res.status_code != 0x00 {
            return Err(Error::RmcppCommand(res.status_code));
        }

        Ok(res)
    }
}

// sec 13.23
#[derive(Debug)]
pub struct RakpMessage4 {
    message_tag: u8,
    status_code: u8,
    remote_id: u32,
    integrity: Option<Vec<u8>>,
}

impl RakpMessage4 {
    pub fn message_tag(&self) -> u8 {
        self.message_tag
    }

    pub fn status_code(&self) -> u8 {
        self.status_code
    }

    pub fn remote_id(&self) -> u32 {
        self.remote_id
    }

    pub fn integrity(&self) -> Option<&[u8]> {
        self.integrity.as_deref()
    }

    pub fn parse(response: &[u8], integrity: IntegrityAlgorithm) -> Result<RakpMessage4, Error> {
        let integrity_end = 8 + integrity.key_len();

        let size = response.len();
        if size < integrity_end {
            return Err(Error::InvalidPacketLength);
        }

        let mut res = RakpMessage4 {
            message_tag: response[0],
            status_code: response[1],
            remote_id: u32::from_le_bytes(response[4..8].try_into().unwrap()),
            integrity: None,
        };

        if 8 < size {
            res.integrity = Some(response[8..integrity_end].to_vec());
        }

        if res.status_code != 0x00 {
            return Err(Error::RmcppCommand(res.status_code));
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    #[test]
    fn response_parse_invalid_packet_length() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        match Response::parse(&bytes) {
            Err(Error::InvalidPacketLength) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn response_parse_ipmi_command() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        match Response::parse(&bytes) {
            Err(Error::IpmiCommand(CompletionCode::Error(6))) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn response_parse_ok_no_data() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x07];
        let res = Response::parse(&bytes).unwrap();
        assert_eq!(0, res.rq_addr());
        assert_eq!(1, res.netfn());
        assert_eq!(3, res.rs_addr());
        assert_eq!(4, res.rq_seq());
        assert_eq!(5, res.cmd());
        assert_eq!(CompletionCode::Completed, res.code());
        assert_eq!(None, res.data());
    }

    #[test]
    fn response_parse_ok_data() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x07, 0x08];
        let res = Response::parse(&bytes).unwrap();
        assert_eq!(0, res.rq_addr());
        assert_eq!(1, res.netfn());
        assert_eq!(3, res.rs_addr());
        assert_eq!(4, res.rq_seq());
        assert_eq!(5, res.cmd());
        assert_eq!(CompletionCode::Completed, res.code());
        assert_eq!(Some(&[0x07][..]), res.data());
    }

    #[test]
    fn rmcpp_open_response_parse_invalid_packet_length() {
        let bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        match RmcppOpenResponse::parse(&bytes) {
            Err(Error::InvalidPacketLength) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rmcpp_open_response_parse_rmcpp_command() {
        let bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        match RmcppOpenResponse::parse(&bytes) {
            Err(Error::RmcppCommand(1)) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rmcpp_open_response_parse_ok() {
        let bytes = vec![
            0x00, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let res = RmcppOpenResponse::parse(&bytes).unwrap();
        assert_eq!(0, res.message_tag());
        assert_eq!(0, res.status_code());
        assert_eq!(PrivilegeLevel::User, res.priv_level());
        assert_eq!(117835012, res.remote_id());
        assert_eq!(16779528, res.session_id());
        assert_eq!(AuthenticationAlgorithm::Oem(6), res.authentication());
        assert_eq!(IntegrityAlgorithm::HmacSha256_128, res.integrity());
        assert_eq!(ConfidentialityAlgorithm::XRC4_128, res.confidentiality());
    }

    #[test]
    fn rakp2_parse_invalid_packet_length() {
        let bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        match RakpMessage2::parse(&bytes, AuthenticationAlgorithm::None) {
            Err(Error::InvalidPacketLength) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rakp2_parse_rmcpp_command() {
        let bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ];
        match RakpMessage2::parse(&bytes, AuthenticationAlgorithm::None) {
            Err(Error::RmcppCommand(1)) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rakp2_parse_ok() {
        let bytes = vec![
            0x00, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ];
        let res = RakpMessage2::parse(&bytes, AuthenticationAlgorithm::None).unwrap();
        assert_eq!(0, res.message_tag());
        assert_eq!(0, res.status_code());
        assert_eq!(117835012, res.remote_id());
        assert_eq!(uuid!("07060504-0908-0100-0203-040506070809"), res.guid());
        assert_eq!(None, res.auth_code())
    }

    #[test]
    fn rakp4_parse_invalid_packet_length() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        match RakpMessage4::parse(&bytes, IntegrityAlgorithm::None) {
            Err(Error::InvalidPacketLength) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rakp4_parse_rmcpp_command() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        match RakpMessage4::parse(&bytes, IntegrityAlgorithm::None) {
            Err(Error::RmcppCommand(1)) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rakp4_parse_ok() {
        let bytes = vec![0x00, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let res = RakpMessage4::parse(&bytes, IntegrityAlgorithm::None).unwrap();
        assert_eq!(0, res.message_tag());
        assert_eq!(0, res.status_code());
        assert_eq!(117835012, res.remote_id());
        assert_eq!(None, res.integrity())
    }
}
