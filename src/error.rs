use crate::ipmi::CompletionCode;
use aes::cipher::block_padding;
use hmac::digest;
use std::array::TryFromSliceError;
use std::io;

#[derive(Debug)]
pub enum Error {
    Bind(io::Error),
    BlockSize(TryFromSliceError),
    Decrypt(block_padding::Error),
    Hash(digest::InvalidLength),
    Integrity,
    InvalidPacketLength,
    InvalidUsernameLength,
    IpmiCommand(CompletionCode),
    RecvPacket(io::Error),
    RmcppCommand(u8),
    SendPacket(io::Error),
}

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Error::BlockSize(error)
    }
}

impl From<block_padding::Error> for Error {
    fn from(error: block_padding::Error) -> Self {
        Error::Decrypt(error)
    }
}

impl From<digest::InvalidLength> for Error {
    fn from(error: digest::InvalidLength) -> Self {
        Error::Hash(error)
    }
}
