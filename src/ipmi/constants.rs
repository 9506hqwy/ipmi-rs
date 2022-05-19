use std::str::FromStr;

// sec 13.6
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthType {
    None = 0x00,
    MD2 = 0x01,
    MD5 = 0x02,
    Password = 0x04,
    Oem = 0x05,
    Format = 0x06,
}

// sec 13.28
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthenticationAlgorithm {
    None,
    HmacSha1,
    HmacMd5,
    HmacSha256,
    Oem(u8),
}

impl AuthenticationAlgorithm {
    pub fn key_len(&self) -> usize {
        match *self {
            AuthenticationAlgorithm::None => 0,
            AuthenticationAlgorithm::HmacSha1 => 20,
            AuthenticationAlgorithm::HmacMd5 => 16,
            AuthenticationAlgorithm::HmacSha256 => 32,
            _ => unimplemented!(),
        }
    }
}

impl From<u8> for AuthenticationAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AuthenticationAlgorithm::None,
            0x01 => AuthenticationAlgorithm::HmacSha1,
            0x02 => AuthenticationAlgorithm::HmacMd5,
            0x03 => AuthenticationAlgorithm::HmacSha256,
            _ => AuthenticationAlgorithm::Oem(value),
        }
    }
}

impl From<AuthenticationAlgorithm> for u8 {
    fn from(value: AuthenticationAlgorithm) -> Self {
        match value {
            AuthenticationAlgorithm::None => 0x00,
            AuthenticationAlgorithm::HmacSha1 => 0x01,
            AuthenticationAlgorithm::HmacMd5 => 0x02,
            AuthenticationAlgorithm::HmacSha256 => 0x03,
            AuthenticationAlgorithm::Oem(v) => v,
        }
    }
}

// sec 28.3
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChassisPowerState {
    PowerDown = 0x00,
    PowerUp = 0x01,
    PowerCycle = 0x02,
    HardReset = 0x03,
    Diagnostic = 0x04,
    Acpi = 0x05,
}

impl FromStr for ChassisPowerState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "powerdown" => Ok(ChassisPowerState::PowerDown),
            "powerup" => Ok(ChassisPowerState::PowerUp),
            "powercycle" => Ok(ChassisPowerState::PowerCycle),
            "hardreset" => Ok(ChassisPowerState::HardReset),
            "diagnostic" => Ok(ChassisPowerState::Diagnostic),
            "acpi" => Ok(ChassisPowerState::Acpi),
            _ => Err(s.to_string()),
        }
    }
}

// Appendix G
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommandApp {
    GetChannelAuthenticationCapabilities = 0x38,
    SetSessionPrivilegeLevel = 0x3B,
    CloseSession = 0x3C,
}

impl From<CommandApp> for u8 {
    fn from(cmd: CommandApp) -> Self {
        match cmd {
            CommandApp::GetChannelAuthenticationCapabilities => 0x38,
            CommandApp::SetSessionPrivilegeLevel => 0x3B,
            CommandApp::CloseSession => 0x3C,
        }
    }
}

// sec 5.2
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CompletionCode {
    Completed,
    Error(u8),
}

impl From<u8> for CompletionCode {
    fn from(value: u8) -> Self {
        match value {
            0 => CompletionCode::Completed,
            _ => CompletionCode::Error(value),
        }
    }
}

// Appendix G
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommandChassis {
    GetChassisStatus = 0x01,
    ChassisControl = 0x02,
}

impl From<CommandChassis> for u8 {
    fn from(cmd: CommandChassis) -> Self {
        match cmd {
            CommandChassis::GetChassisStatus => 0x01,
            CommandChassis::ChassisControl => 0x02,
        }
    }
}

// sec 13.28.5
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConfidentialityAlgorithm {
    None,
    AesCbc128,
    XRC4_128,
    XRC4_40,
    Oem(u8),
}

impl ConfidentialityAlgorithm {
    pub fn key_len(self) -> usize {
        match self {
            ConfidentialityAlgorithm::None => 0,
            ConfidentialityAlgorithm::AesCbc128 => 16,
            ConfidentialityAlgorithm::XRC4_128 => 16,
            ConfidentialityAlgorithm::XRC4_40 => 5,
            _ => unimplemented!(),
        }
    }
}

impl From<u8> for ConfidentialityAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ConfidentialityAlgorithm::None,
            0x01 => ConfidentialityAlgorithm::AesCbc128,
            0x02 => ConfidentialityAlgorithm::XRC4_128,
            0x03 => ConfidentialityAlgorithm::XRC4_40,
            _ => ConfidentialityAlgorithm::Oem(value),
        }
    }
}

impl From<ConfidentialityAlgorithm> for u8 {
    fn from(value: ConfidentialityAlgorithm) -> Self {
        match value {
            ConfidentialityAlgorithm::None => 0x00,
            ConfidentialityAlgorithm::AesCbc128 => 0x01,
            ConfidentialityAlgorithm::XRC4_128 => 0x02,
            ConfidentialityAlgorithm::XRC4_40 => 0x03,
            ConfidentialityAlgorithm::Oem(v) => v,
        }
    }
}

// sec 13.28.4
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IntegrityAlgorithm {
    None,
    HmacSha1_96,
    HmacMd5_128,
    Md5_128,
    HmacSha256_128,
    Oem(u8),
}

impl IntegrityAlgorithm {
    pub fn key_len(self) -> usize {
        match self {
            IntegrityAlgorithm::None => 0,
            IntegrityAlgorithm::HmacSha1_96 => 12,
            IntegrityAlgorithm::HmacMd5_128 => 16,
            IntegrityAlgorithm::Md5_128 => 16,
            IntegrityAlgorithm::HmacSha256_128 => 16,
            _ => unimplemented!(),
        }
    }
}

impl From<u8> for IntegrityAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0x00 => IntegrityAlgorithm::None,
            0x01 => IntegrityAlgorithm::HmacSha1_96,
            0x02 => IntegrityAlgorithm::HmacMd5_128,
            0x03 => IntegrityAlgorithm::Md5_128,
            0x04 => IntegrityAlgorithm::HmacSha256_128,
            _ => IntegrityAlgorithm::Oem(value),
        }
    }
}

impl From<IntegrityAlgorithm> for u8 {
    fn from(value: IntegrityAlgorithm) -> Self {
        match value {
            IntegrityAlgorithm::None => 0x00,
            IntegrityAlgorithm::HmacSha1_96 => 0x01,
            IntegrityAlgorithm::HmacMd5_128 => 0x02,
            IntegrityAlgorithm::Md5_128 => 0x03,
            IntegrityAlgorithm::HmacSha256_128 => 0x04,
            IntegrityAlgorithm::Oem(v) => v,
        }
    }
}

// sec 5.1
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetworkFunctionRequestCode {
    Chassis,
    Bridge,
    Sensor,
    App,
    Firmware,
    Storage,
    Transport,
}

impl NetworkFunctionRequestCode {
    pub fn request(&self) -> u8 {
        match *self {
            NetworkFunctionRequestCode::Chassis => 0x00,
            NetworkFunctionRequestCode::Bridge => 0x02,
            NetworkFunctionRequestCode::Sensor => 0x04,
            NetworkFunctionRequestCode::App => 0x06,
            NetworkFunctionRequestCode::Firmware => 0x08,
            NetworkFunctionRequestCode::Storage => 0x0A,
            NetworkFunctionRequestCode::Transport => 0x0C,
        }
    }
}

// sec 13.27.3
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PayloadType {
    Ipmi,
    Sol,
    RmcpOpenRequest,
    RmcpOpenResponse,
    RakpMessage1,
    RakpMessage2,
    RakpMessage3,
    RakpMessage4,
    Oem(u8),
}

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        match value {
            PayloadType::Ipmi => 0x00,
            PayloadType::Sol => 0x01,
            PayloadType::RmcpOpenRequest => 0x10,
            PayloadType::RmcpOpenResponse => 0x11,
            PayloadType::RakpMessage1 => 0x12,
            PayloadType::RakpMessage2 => 0x13,
            PayloadType::RakpMessage3 => 0x014,
            PayloadType::RakpMessage4 => 0x15,
            PayloadType::Oem(v) => v,
        }
    }
}

// sec 13.17
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrivilegeLevel {
    None = 0x00,
    Callback = 0x01,
    User = 0x02,
    Operator = 0x03,
    Administrator = 0x04,
    Oem = 0x05,
}

impl From<u8> for PrivilegeLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => PrivilegeLevel::None,
            1 => PrivilegeLevel::Callback,
            2 => PrivilegeLevel::User,
            3 => PrivilegeLevel::Operator,
            4 => PrivilegeLevel::Administrator,
            5 => PrivilegeLevel::Oem,
            _ => panic!(),
        }
    }
}
