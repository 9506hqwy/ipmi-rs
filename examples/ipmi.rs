use clap::{Arg, ArgMatches, Command};
use ipmi::error::Error;
use ipmi::ipmi::ChassisPowerState;
use std::str::FromStr;

fn main() -> Result<(), Error> {
    env_logger::init();

    match cmd_ipmi().get_matches().subcommand() {
        Some(("chassis", args)) => match args.subcommand() {
            Some(("status", args)) => run_chassis_status(args)?,
            Some(("control", args)) => run_chassis_control(args)?,
            _ => cmd_chassis().print_long_help().unwrap(),
        },
        _ => {
            cmd_ipmi().print_long_help().unwrap();
        }
    }

    Ok(())
}

fn cmd_ipmi() -> Command<'static> {
    Command::new("IPMI")
        .version("0.1.0")
        .subcommand(cmd_chassis())
}

fn cmd_chassis() -> Command<'static> {
    Command::new("chassis")
        .subcommand(cmd_chassis_control())
        .subcommand(cmd_chassis_status())
}

fn cmd_chassis_control() -> Command<'static> {
    Command::new("control")
        .arg(Arg::new("addr").required(true).index(1))
        .arg(Arg::new("username").required(true).index(2))
        .arg(Arg::new("password").required(true).index(3))
        .arg(Arg::new("state").required(true).index(4))
}

fn cmd_chassis_status() -> Command<'static> {
    Command::new("status")
        .arg(Arg::new("addr").required(true).index(1))
        .arg(Arg::new("username").required(true).index(2))
        .arg(Arg::new("password").required(true).index(3))
}

fn run_chassis_control(args: &ArgMatches) -> Result<(), Error> {
    let addr = args.value_of("addr").unwrap();
    let username = args.value_of("username").unwrap();
    let password = args.value_of("password").unwrap();
    let state = args.value_of("state").unwrap();
    let ps = ChassisPowerState::from_str(state).unwrap();
    ipmi::run_chassis_control(addr, username, password, ps)?;
    Ok(())
}

fn run_chassis_status(args: &ArgMatches) -> Result<(), Error> {
    let addr = args.value_of("addr").unwrap();
    let username = args.value_of("username").unwrap();
    let password = args.value_of("password").unwrap();
    ipmi::run_chassis_status(addr, username, password)?;
    Ok(())
}
