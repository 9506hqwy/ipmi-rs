pub mod error;
pub mod ipmi;
pub mod rmcp;

use self::error::Error;
use self::ipmi::{
    command, AuthenticationAlgorithm, ChassisPowerState, Client, ConfidentialityAlgorithm,
    IntegrityAlgorithm,
};
use log::trace;
use std::net::{ToSocketAddrs, UdpSocket};

pub fn run_chassis_status<A: ToSocketAddrs>(
    remote: A,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::Bind)?;
    trace!("binded: {}", socket.local_addr().unwrap());

    let mut client = Client::new(socket, remote, username, password)?;

    open_session(&mut client)?;

    let res = command::set_privilege_level(&client, 1)?;
    trace!("set privilege level: {:?}", res);

    let res = command::get_chassis_status(&client, 2)?;
    trace!("get chassis status: {:?}", res);

    let ps = res.data().unwrap()[0] & 0x01;
    if ps == 0 {
        println!("power off.");
    } else {
        println!("power on.");
    }

    let res = command::close_session(&client, 3)?;
    trace!("close session: {:?}", res);

    Ok(())
}

pub fn run_chassis_control<A: ToSocketAddrs>(
    remote: A,
    username: &str,
    password: &str,
    state: ChassisPowerState,
) -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::Bind)?;
    trace!("binded: {}", socket.local_addr().unwrap());

    let mut client = Client::new(socket, remote, username, password)?;

    open_session(&mut client)?;

    let res = command::set_privilege_level(&client, 1)?;
    trace!("set privilege level: {:?}", res);

    let res = command::control_chassis(&client, 2, state)?;
    trace!("control chassis: {:?}", res);

    let res = command::close_session(&client, 3)?;
    trace!("close session: {:?}", res);

    Ok(())
}

fn open_session<A: ToSocketAddrs>(client: &mut Client<A>) -> Result<(), Error> {
    let remote_id = u32::from_le_bytes(rand::random::<[u8; 4]>());

    let res = command::get_channel_authentication_cap(client)?;
    trace!("get channel authentication: {:?}", res);

    let res = command::open_rmcpp_session(
        client,
        remote_id,
        AuthenticationAlgorithm::HmacSha1,
        IntegrityAlgorithm::HmacSha1_96,
        ConfidentialityAlgorithm::AesCbc128,
    )?;
    trace!("open rmcpp session: {:?}", res);

    let res = command::rakp_message_1(client)?;
    trace!("RAKP1: {:?}", res);

    let res = command::rakp_message_3(client)?;
    trace!("RAKP3: {:?}", res);

    Ok(())
}
