use crate::ipmi::CompletionCode;
use aes::cipher::inout;
use hmac::digest::crypto_common;
use std::io;

#[derive(Debug)]
pub enum Error {
    Bind(io::Error),
    Decrypt(inout::block_padding::UnpadError),
    Encrypt(inout::PadError),
    Hash(crypto_common::InvalidLength),
    Integrity,
    InvalidPacketLength,
    InvalidUsernameLength,
    IpmiCommand(CompletionCode),
    RecvPacket(io::Error),
    RmcppCommand(u8),
    SendPacket(io::Error),
}

impl From<inout::block_padding::UnpadError> for Error {
    fn from(error: inout::block_padding::UnpadError) -> Self {
        Error::Decrypt(error)
    }
}

impl From<inout::PadError> for Error {
    fn from(error: inout::PadError) -> Self {
        Error::Encrypt(error)
    }
}

impl From<crypto_common::InvalidLength> for Error {
    fn from(error: crypto_common::InvalidLength) -> Self {
        Error::Hash(error)
    }
}
