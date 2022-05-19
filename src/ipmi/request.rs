use super::{
    AuthenticationAlgorithm, ChassisPowerState, CommandApp, CommandChassis,
    ConfidentialityAlgorithm, IntegrityAlgorithm, NetworkFunctionRequestCode, PrivilegeLevel,
};
use std::convert::Into;
use std::convert::TryFrom;

// sec 13.8
#[derive(Debug)]
pub struct Request {
    rs_addr: u8,
    netfn: u8,
    rq_addr: u8,
    rq_seq: u8,
    cmd: u8,
    data: Option<Vec<u8>>,
}

impl From<Request> for Vec<u8> {
    fn from(req: Request) -> Self {
        let mut bytes = vec![req.rs_addr, req.netfn];

        let checksum1 = checksum(&[req.rs_addr, req.netfn]);
        bytes.push(checksum1);

        bytes.push(req.rq_addr);

        bytes.push(req.rq_seq);

        bytes.push(req.cmd);

        let mut checksum2 = vec![req.rq_addr, req.rq_seq, req.cmd];

        if let Some(data) = req.data {
            checksum2.extend_from_slice(&data);
            let c = checksum(checksum2.as_slice());

            bytes.extend_from_slice(&data);
            bytes.push(c);
        } else {
            bytes.push(checksum(checksum2.as_slice()));
        }

        bytes
    }
}

impl Request {
    pub fn new(
        netfn: NetworkFunctionRequestCode,
        cmd: impl Into<u8>,
        data: Option<Vec<u8>>,
    ) -> Self {
        // rsLUN 分をシフトする。
        let fixed_netfn = netfn.request() << 2;

        let fixed_cmd = cmd.into();

        Request {
            rs_addr: 0x20, // BMC
            netfn: fixed_netfn,
            rq_addr: 0x81, // Remote Console
            rq_seq: 0,
            cmd: fixed_cmd,
            data,
        }
    }

    pub fn pkt_len(&self) -> usize {
        7 + self.data.as_ref().map(|d| d.len()).unwrap_or(0)
    }

    // sec 13.29
    pub fn padding(self, block_size: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.into();
        let pad_size = block_size - ((bytes.len() + 1) % block_size);
        for i in 1..=pad_size {
            bytes.push(u8::try_from(i).unwrap());
        }
        bytes.push(u8::try_from(pad_size).unwrap());
        bytes
    }
}

// sec 13.17
#[derive(Debug)]
pub struct RmcppOpenRequest {
    message_tag: u8,
    priv_level: u8,
    remote_id: u32,
    authentication: u64,
    integrity: u64,
    confidentiality: u64,
}

impl From<RmcppOpenRequest> for Vec<u8> {
    fn from(req: RmcppOpenRequest) -> Self {
        let mut bytes = vec![req.message_tag, req.priv_level, 0x00, 0x00];

        bytes.extend_from_slice(&req.remote_id.to_le_bytes());

        bytes.extend_from_slice(&req.authentication.to_le_bytes());

        bytes.extend_from_slice(&req.integrity.to_le_bytes());

        bytes.extend_from_slice(&req.confidentiality.to_le_bytes());

        bytes
    }
}

impl RmcppOpenRequest {
    pub fn new(
        remote_id: u32,
        authentication: AuthenticationAlgorithm,
        integrity: IntegrityAlgorithm,
        confidentiality: ConfidentialityAlgorithm,
    ) -> Self {
        let a: u64 = ((u8::from(authentication) as u64) << 32) + 0x0000_0000_0800_0000;
        let i: u64 = ((u8::from(integrity) as u64) << 32) + 0x0000_0000_0800_0001;
        let c: u64 = ((u8::from(confidentiality) as u64) << 32) + 0x0000_0000_0800_0002;
        RmcppOpenRequest {
            message_tag: 0,
            priv_level: 0, // Highest level matching.
            remote_id,
            authentication: a,
            integrity: i,
            confidentiality: c,
        }
    }

    pub fn pkt_len(&self) -> usize {
        32
    }
}

// sec 13.20
#[derive(Debug)]
pub struct RakpMessage1 {
    message_tag: u8,
    session_id: u32,
    rm: u128,
    priv_level: u8,
    username_len: u8,
    username: Option<Vec<u8>>,
}

impl From<RakpMessage1> for Vec<u8> {
    fn from(msg: RakpMessage1) -> Self {
        let mut bytes = vec![msg.message_tag, 0x00, 0x00, 0x00];

        bytes.extend_from_slice(&msg.session_id.to_le_bytes());

        bytes.extend_from_slice(&msg.rm.to_le_bytes());

        bytes.push(msg.priv_level + 0x10);

        bytes.push(0x00);
        bytes.push(0x00);

        bytes.push(msg.username_len);

        if let Some(u) = msg.username {
            bytes.extend_from_slice(u.as_slice());
        }

        bytes
    }
}

impl RakpMessage1 {
    pub fn new(
        session_id: u32,
        rm: u128,
        priv_level: PrivilegeLevel,
        username: &str,
    ) -> RakpMessage1 {
        RakpMessage1 {
            message_tag: 0,
            session_id,
            rm,
            priv_level: priv_level as u8,
            username_len: u8::try_from(username.len()).unwrap(),
            username: Some(username.as_bytes().to_vec()),
        }
    }

    pub fn pkt_len(&self) -> usize {
        28 + self.username.as_ref().map(|u| u.len()).unwrap_or(0)
    }
}

// sec 13.22
#[derive(Debug)]
pub struct RakpMessage3 {
    message_tag: u8,
    status_code: u8,
    session_id: u32,
    auth_code: Option<Vec<u8>>,
}

impl From<RakpMessage3> for Vec<u8> {
    fn from(msg: RakpMessage3) -> Self {
        let mut bytes = vec![msg.message_tag, msg.status_code, 0x00, 0x00];

        bytes.extend_from_slice(&msg.session_id.to_le_bytes());

        if let Some(auth_code) = msg.auth_code {
            bytes.extend_from_slice(auth_code.as_slice());
        }

        bytes
    }
}

impl RakpMessage3 {
    pub fn new(status_code: u8, session_id: u32, auth_code: Option<&[u8]>) -> RakpMessage3 {
        RakpMessage3 {
            message_tag: 0,
            status_code,
            session_id,
            auth_code: auth_code.map(|a| a.to_vec()),
        }
    }

    pub fn pkt_len(&self) -> usize {
        8 + self.auth_code.as_ref().map(|a| a.len()).unwrap_or(0)
    }
}

// sec 13.8
fn checksum(values: &[u8]) -> u8 {
    let sum: u8 = values.iter().fold(0, |acc, &x| acc.wrapping_add(x));
    (sum ^ 0xFF).wrapping_add(1)
}

// sec 13.17
pub fn open_rmcpp_session(
    remote_id: u32,
    authentication: AuthenticationAlgorithm,
    integrity: IntegrityAlgorithm,
    confidentiality: ConfidentialityAlgorithm,
) -> RmcppOpenRequest {
    RmcppOpenRequest::new(remote_id, authentication, integrity, confidentiality)
}

// sec 22.13
pub fn get_channel_authentication_cap(priv_level: PrivilegeLevel) -> Request {
    let data = vec![0x8E, priv_level as u8];

    Request::new(
        NetworkFunctionRequestCode::App,
        CommandApp::GetChannelAuthenticationCapabilities,
        Some(data),
    )
}

// sec 22.18
pub fn set_privilege_level(priv_level: PrivilegeLevel) -> Request {
    let data = vec![priv_level as u8];

    Request::new(
        NetworkFunctionRequestCode::App,
        CommandApp::SetSessionPrivilegeLevel,
        Some(data),
    )
}

// sec 22.19
pub fn close_session(session_id: u32) -> Request {
    Request::new(
        NetworkFunctionRequestCode::App,
        CommandApp::CloseSession,
        Some(session_id.to_le_bytes().to_vec()),
    )
}

// sec 28.2
pub fn get_chassis_status() -> Request {
    Request::new(
        NetworkFunctionRequestCode::Chassis,
        CommandChassis::GetChassisStatus,
        None,
    )
}

// sec 28.3
pub fn control_chassis(state: ChassisPowerState) -> Request {
    let data = vec![state as u8];

    Request::new(
        NetworkFunctionRequestCode::Chassis,
        CommandChassis::ChassisControl,
        Some(data),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_from() {
        let req = Request::new(NetworkFunctionRequestCode::App, 0x01, None);
        let bytes: Vec<u8> = req.into();
        assert_eq!(vec![0x20, 0x18, 0xC8, 0x81, 0x00, 0x01, 0x7E], bytes);
    }

    #[test]
    fn request_pkt_len_no_data() {
        let req = Request::new(NetworkFunctionRequestCode::App, 0x01, None);
        assert_eq!(7, req.pkt_len());
    }

    #[test]
    fn request_pkt_len_with_data() {
        let req = Request::new(NetworkFunctionRequestCode::App, 0x01, Some(vec![0x01]));
        assert_eq!(8, req.pkt_len());
    }

    #[test]
    fn request_padding_no_data() {
        let req = Request::new(NetworkFunctionRequestCode::App, 0x01, None);
        assert_eq!(
            vec![0x20, 0x18, 0xC8, 0x81, 0x00, 0x01, 0x7E, 0x01, 0x02, 0x02],
            req.padding(10)
        );
    }

    #[test]
    fn request_padding_with_data() {
        let req = Request::new(NetworkFunctionRequestCode::App, 0x01, Some(vec![0x01]));
        assert_eq!(
            vec![0x20, 0x18, 0xC8, 0x81, 0x00, 0x01, 0x01, 0x7D, 0x01, 0x01],
            req.padding(10)
        );
    }

    #[test]
    fn rmcpp_open_request_from() {
        let req = RmcppOpenRequest::new(
            1,
            AuthenticationAlgorithm::HmacSha1,
            IntegrityAlgorithm::HmacMd5_128,
            ConfidentialityAlgorithm::XRC4_40,
        );

        let bytes: Vec<u8> = req.into();
        let refs = vec![
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08,
            0x03, 0x00, 0x00, 0x00,
        ];
        assert_eq!(refs, bytes);
    }

    #[test]
    fn rmcpp_open_request_len() {
        let req = RmcppOpenRequest::new(
            1,
            AuthenticationAlgorithm::HmacSha1,
            IntegrityAlgorithm::HmacMd5_128,
            ConfidentialityAlgorithm::XRC4_40,
        );
        assert_eq!(32, req.pkt_len());
    }

    #[test]
    fn rakp1_from() {
        let req = RakpMessage1::new(1, 2, PrivilegeLevel::Operator, "username");
        let bytes: Vec<u8> = req.into();
        assert_eq!(
            vec![
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x08,
                0x75, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
            ],
            bytes
        );
    }

    #[test]
    fn rakp1_pkt_len() {
        let req = RakpMessage1::new(1, 2, PrivilegeLevel::Operator, "username");
        assert_eq!(36, req.pkt_len())
    }

    #[test]
    fn rakp3_from_no_data() {
        let req = RakpMessage3::new(1, 2, None);
        let bytes: Vec<u8> = req.into();
        assert_eq!(vec![0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,], bytes);
    }

    #[test]
    fn rakp3_from_with_data() {
        let req = RakpMessage3::new(1, 2, Some(&[0x03]));
        let bytes: Vec<u8> = req.into();
        assert_eq!(
            vec![0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03],
            bytes
        );
    }

    #[test]
    fn rakp3_pkt_len() {
        let req = RakpMessage3::new(1, 2, None);
        assert_eq!(8, req.pkt_len())
    }

    #[test]
    fn rakp3_pkt_len_with_data() {
        let req = RakpMessage3::new(1, 2, Some(&[0x03]));
        assert_eq!(9, req.pkt_len())
    }
}
