use clap::{Arg, ArgMatches, Command};
use ipmi::error::Error;
use ipmi::ipmi::ChassisPowerState;
use std::net::Ipv4Addr;
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

fn cmd_ipmi() -> Command {
    Command::new("IPMI")
        .version("0.2.0")
        .subcommand(cmd_chassis())
}

fn cmd_chassis() -> Command {
    Command::new("chassis")
        .subcommand(cmd_chassis_control())
        .subcommand(cmd_chassis_status())
}

fn cmd_chassis_control() -> Command {
    Command::new("control")
        .arg(Arg::new("addr").required(true).index(1))
        .arg(Arg::new("username").required(true).index(2))
        .arg(Arg::new("password").required(true).index(3))
        .arg(Arg::new("state").required(true).index(4).value_parser([
            "PowerDown",
            "PowerUp",
            "PowerCycle",
            "HardReset",
            "Diagnostic",
            "Acpi",
        ]))
}

fn cmd_chassis_status() -> Command {
    Command::new("status")
        .arg(Arg::new("addr").required(true).index(1))
        .arg(Arg::new("username").required(true).index(2))
        .arg(Arg::new("password").required(true).index(3))
}

fn run_chassis_control(args: &ArgMatches) -> Result<(), Error> {
    let addr = parse_addr(args.get_one::<String>("addr").unwrap());
    let username = args.get_one::<String>("username").unwrap();
    let password = args.get_one::<String>("password").unwrap();
    let state = args.get_one::<String>("state").unwrap();
    let ps = ChassisPowerState::from_str(state).unwrap();
    ipmi::run_chassis_control(addr, username, password, ps)?;
    Ok(())
}

fn run_chassis_status(args: &ArgMatches) -> Result<(), Error> {
    let addr = parse_addr(args.get_one::<String>("addr").unwrap());
    let username = args.get_one::<String>("username").unwrap();
    let password = args.get_one::<String>("password").unwrap();
    let res = ipmi::run_chassis_status(addr, username, password)?;
    let ps = res[0] & 0x01;
    if ps == 0 {
        println!("power off.");
    } else {
        println!("power on.");
    }
    Ok(())
}

fn parse_addr(value: &str) -> String {
    if value.parse::<Ipv4Addr>().is_ok() {
        format!("{}:623", value)
    } else {
        value.to_string()
    }
}
