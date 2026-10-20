use clap::*;
use log::info;
use simple_logger::SimpleLogger;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{env, fs};

mod ihex;
pub mod parts;
mod programmer;

pub use crate::{ihex::*, parts::*, programmer::*};

fn parse_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if !s.len().is_multiple_of(2) {
        return Err("Hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

/// The 6-byte customer unlock password. The dongle's key field is 8 bytes, so it is padded with two
/// zero bytes.
fn parse_unlock_key(s: &str) -> Result<[u8; 8], Box<dyn std::error::Error>> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 6 {
        return Err(format!("unlock password must be 6 bytes, got {}", bytes.len()).into());
    }
    let mut key = [0u8; 8];
    key[..6].copy_from_slice(&bytes);
    Ok(key)
}

fn parse_addr(s: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).map_err(|e| e.into())
    } else {
        s.parse::<usize>().map_err(|e| e.into())
    }
}

fn parse_group_spec(
    spec: Option<&str>,
    groups: usize,
) -> Result<Vec<bool>, Box<dyn std::error::Error>> {
    let mut selected = vec![false; groups];
    let Some(spec) = spec else {
        return Ok(selected);
    };
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return Ok(vec![true; groups]);
    }
    if spec.is_empty() || spec.eq_ignore_ascii_case("none") {
        return Ok(selected);
    }
    for part in spec.split(',') {
        let part = part.trim();
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.trim().parse::<usize>()?, b.trim().parse::<usize>()?),
            None => {
                let g = part.parse::<usize>()?;
                (g, g)
            }
        };
        if lo > hi {
            return Err(format!("group range {} is inverted", part).into());
        }
        if hi >= groups {
            return Err(format!(
                "group {} is out of range; this part has {} group(s), 0-{}",
                hi,
                groups,
                groups - 1
            )
            .into());
        }
        for slot in selected.iter_mut().take(hi + 1).skip(lo) {
            *slot = true;
        }
    }
    Ok(selected)
}

fn sinolink_args() -> [Arg; 4] {
    [
        arg!(--power_on_time <N> "SinoLink power-on time, 3..27 (default 3)").required(false),
        arg!(--use_reset_pin "SinoLink: drive the reset pin during entry and always run a full entry")
            .action(clap::ArgAction::SetTrue)
            .required(false),
        arg!(--link <LINK> "SinoLink target link: 4wire (default) or 1wire").required(false),
        arg!(--boot_rom "SinoLink: program and erase the boot (ISP) area; only for parts with an ISP region")
            .action(clap::ArgAction::SetTrue)
            .required(false),
    ]
}

fn cli() -> Command {
    Command::new("sinodude")
        .about("programming tool for sinowealth devices")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .author("Karolis Stasaitis")
        .subcommand(
            Command::new("read")
                .short_flag('r')
                .about("Read the chip's code flash and/or data EEPROM into Intel HEX files")
                .arg(arg!(--flash <FILE> "Write the code flash contents to this file").required(false))
                .arg(arg!(--eeprom <FILE> "Write the data EEPROM contents to this file").required(false))
                .group(ArgGroup::new("memory").args(["flash", "eeprom"]).multiple(true).required(true))
                .arg(
                    arg!(-c --programmer <PROGRAMMER>)
                        .value_parser(["sinodude-serial", "sinolink"])
                        .required(true),
                )
                .arg(
                    arg!(-p --part <PART>)
                        .value_parser(PARTS.keys().copied().collect::<Vec<_>>())
                        .required(true),
                )
                .arg(
                    arg!(--port <PORT> "Serial port for sinodude-serial programmer (e.g., /dev/ttyUSB0)")
                        .required(false),
                )
                .arg(
                    arg!(--power <MODE> "Target power for the sinolink programmer: 3v3, 5v or external")
                        .required(false),
                )
                .arg(
                    arg!(--supply <RAIL> "Deprecated spelling of --power")
                        .required(false)
                        .hide(true),
                )
                .args(sinolink_args())
                .arg(
                    arg!(--key <KEY> "Customer password for a protected part (6 bytes hex)")
                        .required(false),
                )
                .arg(
                    arg!(--ignore_part_number "Continue when the die reports a part number that does not match --part")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("write")
                .short_flag('w')
                .about("Write Intel HEX files to the chip's code flash and/or data EEPROM")
                .arg(arg!(--flash <FILE> "Program the code flash from this file").required(false))
                .arg(arg!(--eeprom <FILE> "Program the data EEPROM from this file (erases the whole EEPROM first)").required(false))
                .group(ArgGroup::new("memory").args(["flash", "eeprom"]).multiple(true).required(true))
                .arg(
                    arg!(-c --programmer <PROGRAMMER>)
                        .value_parser(["sinodude-serial", "sinolink"])
                        .required(true),
                )
                .arg(
                    arg!(-p --part <PART>)
                        .value_parser(PARTS.keys().copied().collect::<Vec<_>>())
                        .required(true),
                )
                .arg(
                    arg!(--port <PORT> "Serial port for sinodude-serial programmer (e.g., /dev/ttyUSB0)")
                        .required(false),
                )
                .arg(
                    arg!(--power <MODE> "Target power for the sinolink programmer: 3v3, 5v or external")
                        .required(false),
                )
                .arg(
                    arg!(--supply <RAIL> "Deprecated spelling of --power")
                        .required(false)
                        .hide(true),
                )
                .args(sinolink_args())
                .arg(
                    arg!(--key <KEY> "Customer password for a protected part (6 bytes hex)")
                        .required(false),
                )
                .arg(
                    arg!(--customer_id <CUSTOMER_ID> "Customer ID (4 bytes hex, e.g., 01020304)")
                        .required(false),
                )
                .arg(
                    arg!(--operation_number <OPERATION_NUMBER> "Operation number (2 bytes hex, e.g., 0102)")
                        .required(false),
                )
                .arg(
                    arg!(--customer_option <CUSTOMER_OPTION> "Customer option (hex string)")
                        .required(false),
                )
                .arg(
                    arg!(--security <SECURITY> "Security bits (hex string)")
                        .required(false),
                )
                .arg(
                    arg!(--serial_number <SERIAL_NUMBER> "Serial number (4 bytes hex, e.g., 01020304)")
                        .required(false),
                )
                .arg(
                    arg!(--start_addr <START_ADDR> "Start address for partial write (hex, e.g., 0x1000)")
                        .required(false),
                )
                .arg(
                    arg!(--end_addr <END_ADDR> "End address for partial write (hex, e.g., 0x2000)")
                        .required(false),
                )
                .arg(
                    arg!(--erase_mode <MODE> "Force a vendor erase-mode index (0-5) instead of the part's own. Mode 3 (ICP 0x5E) erases the die's product-identity record, which no write path can restore")
                        .required(false),
                )
                .arg(
                    arg!(--ignore_part_number "Continue when the die reports a part number that does not match --part")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("erase")
                .short_flag('e')
                .about("Erase the chip's flash (mass erase or specific sectors)")
                .arg(
                    arg!(-c --programmer <PROGRAMMER>)
                        .value_parser(["sinodude-serial", "sinolink"])
                        .required(true),
                )
                .arg(
                    arg!(-p --part <PART>)
                        .value_parser(PARTS.keys().copied().collect::<Vec<_>>())
                        .required(true),
                )
                .arg(
                    arg!(--port <PORT> "Serial port for sinodude-serial programmer (e.g., /dev/ttyUSB0)")
                        .required(false),
                )
                .arg(
                    arg!(--power <MODE> "Target power for the sinolink programmer: 3v3, 5v or external")
                        .required(false),
                )
                .arg(
                    arg!(--supply <RAIL> "Deprecated spelling of --power")
                        .required(false)
                        .hide(true),
                )
                .args(sinolink_args())
                .arg(
                    arg!(--key <KEY> "Customer password for a protected part (6 bytes hex)")
                        .required(false),
                )
                .arg(
                    arg!(--start_addr <START_ADDR> "Start address for sector erase (hex, e.g., 0x1000)")
                        .required(false),
                )
                .arg(
                    arg!(--end_addr <END_ADDR> "End address for sector erase (hex, e.g., 0x2000)")
                        .required(false),
                )
                .arg(
                    arg!(--eeprom "Erase the data EEPROM (256-byte pages) instead of code flash")
                        .required(false)
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(--erase_mode <MODE> "Force a vendor erase-mode index (0-5) instead of the part's own. Mode 3 (ICP 0x5E) erases the die's product-identity record, which no write path can restore")
                        .required(false),
                )
                .arg(
                    arg!(--ignore_part_number "Continue when the die reports a part number that does not match --part")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("security")
                .about("Show or apply the chip's per-group read/write protection")
                .arg(
                    arg!(-c --programmer <PROGRAMMER>)
                        .value_parser(["sinodude-serial", "sinolink"])
                        .required(true),
                )
                .arg(
                    arg!(-p --part <PART>)
                        .value_parser(PARTS.keys().copied().collect::<Vec<_>>())
                        .required(true),
                )
                .arg(
                    arg!(--port <PORT> "Serial port for sinodude-serial programmer (e.g., /dev/ttyUSB0)")
                        .required(false),
                )
                .arg(
                    arg!(--power <MODE> "Target power for the sinolink programmer: 3v3, 5v or external")
                        .required(false),
                )
                .arg(
                    arg!(--supply <RAIL> "Deprecated spelling of --power")
                        .required(false)
                        .hide(true),
                )
                .args(sinolink_args())
                .arg(
                    arg!(--key <KEY> "Customer password for a protected part (6 bytes hex)")
                        .required(false),
                )
                .arg(
                    arg!(--ignore_part_number "Continue when the die reports a part number that does not match --part")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                )
                .arg(
                    arg!(--read_protect <GROUPS> "Read-protect these groups: \"all\", or a list like 1,2,5-6,13")
                        .required(false),
                )
                .arg(
                    arg!(--write_protect <GROUPS> "Write-protect these groups: \"all\", or a list like 1,2,5-6,13")
                        .required(false),
                )
                .arg(
                    arg!(--password <PASSWORD> "Set the customer password (6 bytes hex); unlock later with --key <password>")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("sinolink")
                .about("Drive a genuine SinoLink USB dongle directly (diagnostics and raw access)")
                .subcommand_required(true)
                .subcommand(Command::new("probe").about("Show the dongle's version block, power state and stored parameter block"))
                .subcommand(
                    Command::new("dump")
                        .about("Connect and read a range of target memory")
                        .arg(arg!(-p --part <PART>).value_parser(PARTS.keys().copied().collect::<Vec<_>>()).required(true))
                        .arg(arg!(--power <MODE> "Target power: 3v3, 5v or external").required(false))
                        .args(sinolink_args())
                        .arg(arg!(--key <KEY> "Customer password, 6 bytes hex").required(false))
                        .arg(arg!(--addr <ADDR> "Start address").required(false))
                        .arg(arg!(--len <LEN> "Byte count").required(false))
                        .arg(arg!(--region <REGION> "code or custom").required(false))
                        .arg(arg!(--out <FILE> "Write the bytes to this file as Intel HEX").required(false))
                        .arg(arg!(--bin <FILE> "Write the bytes to this file raw").required(false)),
                )
                .subcommand(
                    Command::new("raw")
                        .about("Issue one vendor control-IN and print the reply")
                        .arg(arg!(--req <N> "bRequest").required(true))
                        .arg(arg!(--value <N> "wValue").required(false))
                        .arg(arg!(--index <N> "wIndex").required(false))
                        .arg(arg!(--len <N> "wLength").required(false)),
                ),
        )
}

/// The PARTS keys are static, so the chosen name can outlive the ArgMatches.
fn part_name_static(sub: &ArgMatches) -> &'static str {
    let n = sub
        .get_one::<String>("part")
        .map(|s| s.as_str())
        .unwrap_or("");
    PARTS.keys().find(|k| **k == n).copied().unwrap_or("")
}

fn make_programmer(
    sub: &ArgMatches,
    part: &'static Part,
    cancelled: Arc<AtomicBool>,
) -> Result<Box<dyn Programmer>, Box<dyn std::error::Error>> {
    match sub.get_one::<String>("programmer").map(|s| s.as_str()) {
        Some("sinolink") => Ok(Box::new(SinoLinkProgrammer::new(
            part,
            part_name_static(sub),
            cancelled,
            sinolink_settings(sub)?,
        )?)),
        _ => {
            let port = sub
                .get_one::<String>("port")
                .ok_or("--port is required for the sinodude-serial programmer")?;
            Ok(Box::new(SinodudeSerialProgrammer::new(
                port, part, cancelled,
            )?))
        }
    }
}

/// --power wins; --supply is kept as the older spelling.
fn sinolink_settings(sub: &ArgMatches) -> Result<Settings, Box<dyn std::error::Error>> {
    let power = sub
        .get_one::<String>("power")
        .or_else(|| sub.try_get_one::<String>("supply").ok().flatten());
    let power_on_time = match sub.get_one::<String>("power_on_time") {
        Some(v) => {
            let t: u8 = v.parse()?;
            if !(3..=27).contains(&t) {
                return Err("--power_on_time must be 3..27".into());
            }
            t
        }
        None => 3,
    };
    Ok(Settings {
        power: Power::parse(power.map(|s| s.as_str())),
        link: Link::parse(sub.get_one::<String>("link").map(|s| s.as_str())),
        power_on_time,
        use_reset_pin: sub.get_flag("use_reset_pin"),
        boot_rom: sub.get_flag("boot_rom"),
    })
}

fn sinolink_cmd(
    matches: &ArgMatches,
    cancelled: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let num = |sub: &ArgMatches, k: &str, d: usize| -> Result<usize, Box<dyn std::error::Error>> {
        Ok(match sub.get_one::<String>(k) {
            Some(v) => parse_addr(v)?,
            None => d,
        })
    };
    match matches.subcommand() {
        Some(("probe", _)) => {
            let link = SinoLink::open()?;
            let v = link.version()?;
            println!(
                "firmware:     V{:x}.{:02x}, {}",
                v.major(),
                v.minor(),
                v.personality()
            );
            println!("build:        {:02x?}", &v.raw[..6]);
            println!("unique ID:    {}", hex_string(v.unique_id()));
            println!("power state:  {:?}", link.power_state()?);
            let (code, addr) = link.socket_status()?;
            println!(
                "last status:  {code:#04x} ({}) at {addr:#x}",
                decode_sub_error(code)
            );
            let block = link.read_block()?;
            println!(
                "stored block: ChipType {:#04x}, link {}, power {}, power-on time {}, customer block {:#x}",
                block[3],
                block[4],
                block[5],
                block[6],
                u32::from_le_bytes(block[0x204..0x208].try_into().unwrap())
            );
        }
        Some(("raw", sub)) => {
            let link = SinoLink::open()?;
            let req = num(sub, "req", 0)? as u8;
            let value = num(sub, "value", 0)? as u16;
            let index = num(sub, "index", 0)? as u16;
            let len = num(sub, "len", 64)? as u16;
            if matches!(req, req::SWITCH_TO_DAP | req::ENTER_BOOTLOADER) {
                return Err("that request reboots the dongle into another image".into());
            }
            let d = link.raw_in(req, value, index, len)?;
            println!(
                "req {req:#04x} val {value:#06x} idx {index:#06x} -> ({}) {:02x?}",
                d.len(),
                d
            );
        }
        Some(("dump", sub)) => {
            let name = part_name_static(sub);
            let part = PARTS[name];
            let mut programmer =
                SinoLinkProgrammer::new(part, name, cancelled, sinolink_settings(sub)?)?;
            if let Some(k) = sub.get_one::<String>("key") {
                programmer.set_unlock_key(parse_unlock_key(k)?);
            }
            programmer.read_init()?;
            let addr = num(sub, "addr", 0)? as u32;
            let len = num(sub, "len", 0x100)?;
            let region = match sub.get_one::<String>("region").map(|s| s.as_str()) {
                Some("custom") => Region::Custom,
                _ => Region::Flash,
            };
            let out = programmer.read_region(region, addr, len, "dump")?;
            programmer.finish()?;
            if len <= 0x400 {
                for (i, row) in out.chunks(16).enumerate() {
                    let hex: Vec<String> = row.iter().map(|b| format!("{:02x}", b)).collect();
                    println!("{:06x}  {}", addr as usize + i * 16, hex.join(" "));
                }
            }
            println!("md5 {:x}", md5::compute(&out));
            if let Some(file) = sub.get_one::<String>("bin") {
                fs::write(file, &out)?;
            }
            if let Some(file) = sub.get_one::<String>("out") {
                fs::write(file, to_ihex(out)?)?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn run(cancelled: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("sinolink", sub_matches)) => return sinolink_cmd(sub_matches, cancelled),
        Some(("read", sub_matches)) => {
            let flash_file = sub_matches.get_one::<String>("flash");
            let eeprom_file = sub_matches.get_one::<String>("eeprom");

            let part_name = sub_matches
                .get_one::<String>("part")
                .map(|s| s.as_str())
                .unwrap();

            let part = PARTS.get(part_name).unwrap();
            if eeprom_file.is_some() && part.eeprom_size == 0 {
                return Err(format!("{} has no data EEPROM", part_name).into());
            }

            let mut programmer = make_programmer(sub_matches, part, cancelled.clone())?;
            if let Some(key) = sub_matches.get_one::<String>("key") {
                programmer.set_unlock_key(parse_unlock_key(key)?);
            }
            programmer.set_ignore_part_number(sub_matches.get_flag("ignore_part_number"));
            programmer.read_init()?;
            let flash = flash_file.map(|_| programmer.read_flash()).transpose()?;
            let eeprom = eeprom_file.map(|_| programmer.read_eeprom()).transpose()?;
            programmer.finish()?;

            for (file, data) in [(flash_file, flash), (eeprom_file, eeprom)] {
                if let (Some(file), Some(data)) = (file, data) {
                    info!("{} MD5: {:x}", file, md5::compute(&data));
                    fs::write(file, to_ihex(data)?)?;
                }
            }
        }
        Some(("write", sub_matches)) => {
            let part_name = sub_matches
                .get_one::<String>("part")
                .map(|s| s.as_str())
                .unwrap();

            let part = PARTS.get(part_name).unwrap();

            let firmware = sub_matches
                .get_one::<String>("flash")
                .map(|file| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                    let mut data = from_ihex(&fs::read_to_string(file)?, part.flash_size)?;
                    data.resize(part.flash_size, 0);
                    Ok(data)
                })
                .transpose()?;

            let eeprom = sub_matches
                .get_one::<String>("eeprom")
                .map(|file| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                    if part.eeprom_size == 0 {
                        return Err(format!("{} has no data EEPROM", part_name).into());
                    }
                    let mut data = from_ihex(&fs::read_to_string(file)?, part.eeprom_size)?;
                    data.resize(part.eeprom_size, 0);
                    Ok(data)
                })
                .transpose()?;

            // Parse and validate address range before connecting
            let sector_size = part.sector_size;
            let start_addr = sub_matches
                .get_one::<String>("start_addr")
                .map(|s| parse_addr(s))
                .transpose()?;
            let end_addr = sub_matches
                .get_one::<String>("end_addr")
                .map(|s| parse_addr(s))
                .transpose()?;

            if let Some(addr) = start_addr {
                if addr % sector_size != 0 {
                    return Err(format!(
                        "Start address {:#x} is not aligned to sector size {:#x}",
                        addr, sector_size
                    )
                    .into());
                }
            }
            if let Some(addr) = end_addr {
                if addr % sector_size != 0 {
                    return Err(format!(
                        "End address {:#x} is not aligned to sector size {:#x}",
                        addr, sector_size
                    )
                    .into());
                }
            }

            // Parse custom fields
            let customer_id: Option<[u8; 4]> = sub_matches
                .get_one::<String>("customer_id")
                .map(|s| parse_hex(s))
                .transpose()?
                .map(|v| {
                    if v.len() != 4 {
                        return Err("Customer ID must be exactly 4 bytes");
                    }
                    Ok(v.as_slice().try_into().unwrap())
                })
                .transpose()?;

            let operation_number: Option<[u8; 2]> = sub_matches
                .get_one::<String>("operation_number")
                .map(|s| parse_hex(s))
                .transpose()?
                .map(|v| {
                    if v.len() != 2 {
                        return Err("Operation number must be exactly 2 bytes");
                    }
                    Ok(v.as_slice().try_into().unwrap())
                })
                .transpose()?;

            let customer_option: Option<Vec<u8>> = sub_matches
                .get_one::<String>("customer_option")
                .map(|s| parse_hex(s))
                .transpose()?;

            let security: Option<Vec<u8>> = sub_matches
                .get_one::<String>("security")
                .map(|s| parse_hex(s))
                .transpose()?;

            let serial_number: Option<[u8; 4]> = sub_matches
                .get_one::<String>("serial_number")
                .map(|s| parse_hex(s))
                .transpose()?
                .map(|v| {
                    if v.len() != 4 {
                        return Err("Serial number must be exactly 4 bytes");
                    }
                    Ok(v.as_slice().try_into().unwrap())
                })
                .transpose()?;

            let mut programmer = make_programmer(sub_matches, part, cancelled.clone())?;
            if let Some(key) = sub_matches.get_one::<String>("key") {
                programmer.set_unlock_key(parse_unlock_key(key)?);
            }
            programmer.set_ignore_part_number(sub_matches.get_flag("ignore_part_number"));
            let sectors = match (start_addr, end_addr) {
                (None, None) => None,
                (start, end) => Some((
                    start.unwrap_or(0) as u32,
                    end.unwrap_or(part.flash_size) as u32,
                )),
            };
            programmer.set_project(Project {
                flash: firmware.clone(),
                eeprom: eeprom.clone(),
                eeprom_area: eeprom.is_some(),
                code_options: customer_option.clone(),
                customer_id,
                serial_number,
                erase: firmware.is_some(),
                program: true,
                sectors: sectors.filter(|_| firmware.is_some()),
                ..Project::default()
            });
            programmer.write_init()?;

            // Flash goes first: its mass erase may take the EEPROM with it.
            if let Some(firmware) = &firmware {
                // Use sector-based erase for partial writes, mass erase for full writes
                match (start_addr, end_addr) {
                    (Some(start), Some(end)) => {
                        programmer.erase_sectors(start as u32, end as u32)?;
                    }
                    (Some(start), None) => {
                        programmer.erase_sectors(start as u32, part.flash_size as u32)?;
                    }
                    (None, Some(end)) => {
                        programmer.erase_sectors(0, end as u32)?;
                    }
                    (None, None) => match sub_matches.get_one::<String>("erase_mode") {
                        Some(m) => programmer.mass_erase_with_mode(m.parse::<u8>()?)?,
                        None => programmer.mass_erase()?,
                    },
                }

                // Write all custom fields in one transaction (use stored values as defaults)
                programmer.write_custom_fields(
                    customer_id.as_ref(),
                    operation_number.as_ref(),
                    customer_option.as_deref(),
                    security.as_deref(),
                    serial_number.as_ref(),
                    true, // use_stored_defaults
                )?;

                // Use range write for partial writes, full write otherwise
                match (start_addr, end_addr) {
                    (Some(start), Some(end)) => {
                        programmer.write_flash_range(firmware, start, end)?;
                    }
                    (Some(start), None) => {
                        programmer.write_flash_range(firmware, start, firmware.len())?;
                    }
                    (None, Some(end)) => {
                        programmer.write_flash_range(firmware, 0, end)?;
                    }
                    (None, None) => {
                        programmer.write_flash(firmware)?;
                    }
                }
            }

            if let Some(eeprom) = &eeprom {
                programmer.write_eeprom(eeprom)?;
            }

            programmer.finish()?;
        }
        Some(("security", sub_matches)) => {
            let part_name = sub_matches
                .get_one::<String>("part")
                .map(|s| s.as_str())
                .unwrap();
            let part = PARTS.get(part_name).unwrap();

            let mut programmer = make_programmer(sub_matches, part, cancelled.clone())?;
            if let Some(key) = sub_matches.get_one::<String>("key") {
                programmer.set_unlock_key(parse_unlock_key(key)?);
            }
            programmer.set_ignore_part_number(sub_matches.get_flag("ignore_part_number"));

            let groups = part.protect_group_count();
            let group_size = part.protect_group_size();

            let read_spec = sub_matches.get_one::<String>("read_protect");
            let write_spec = sub_matches.get_one::<String>("write_protect");
            let new_password: Option<[u8; PROTECTION_PASSWORD_LEN]> =
                match sub_matches.get_one::<String>("password") {
                    Some(p) => Some(
                        parse_hex(p)?
                            .as_slice()
                            .try_into()
                            .map_err(|_| "Password must be exactly 6 bytes")?,
                    ),
                    None => None,
                };
            let applying = read_spec.is_some() || write_spec.is_some() || new_password.is_some();
            programmer.set_project(Project {
                security: applying,
                read_protect: parse_group_spec(read_spec.map(|s| s.as_str()), groups)?,
                write_protect: parse_group_spec(write_spec.map(|s| s.as_str()), groups)?,
                new_password,
                ..Project::default()
            });
            programmer.read_init()?;

            if read_spec.is_none() && write_spec.is_none() && new_password.is_none() {
                let prot = programmer.read_protection()?;
                println!(
                    "Protection: {} group(s) of {:#x} bytes ({} sector(s) per bit)",
                    groups,
                    group_size,
                    part.sectors_per_protect_bit()
                );
                println!("Record: {}", hex_string(&prot.record));
                let mut any = false;
                for g in 0..groups {
                    if prot.read[g] || prot.write[g] {
                        any = true;
                        println!(
                            "  group {:<2} {:#06x}-{:#06x}  {}{}",
                            g,
                            g * group_size,
                            (g + 1) * group_size - 1,
                            if prot.read[g] { "read " } else { "" },
                            if prot.write[g] { "write" } else { "" },
                        );
                    }
                }
                if !any {
                    println!("  (unprotected)");
                }
            } else {
                let read = parse_group_spec(read_spec.map(|s| s.as_str()), groups)?;
                let write = parse_group_spec(write_spec.map(|s| s.as_str()), groups)?;
                eprintln!(
                    "Applying protection: {} read-protected, {} write-protected, of {} group(s)",
                    read.iter().filter(|&&b| b).count(),
                    write.iter().filter(|&&b| b).count(),
                    groups
                );
                if new_password.is_some() {
                    eprintln!("Setting a customer password.");
                }
                eprintln!("This cannot be undone without a full mass erase.");
                programmer.apply_protection(&read, &write, new_password.as_ref())?;
                eprintln!("Protection applied.");
            }

            programmer.finish()?;
        }
        Some(("erase", sub_matches)) => {
            let part_name = sub_matches
                .get_one::<String>("part")
                .map(|s| s.as_str())
                .unwrap();

            let part = PARTS.get(part_name).unwrap();
            if sub_matches.get_flag("eeprom") && part.eeprom_size == 0 {
                return Err(format!("{} has no data EEPROM", part_name).into());
            }

            // Parse and validate address range before connecting
            let sector_size = part.sector_size;
            let start_addr = sub_matches
                .get_one::<String>("start_addr")
                .map(|s| parse_addr(s))
                .transpose()?;
            let end_addr = sub_matches
                .get_one::<String>("end_addr")
                .map(|s| parse_addr(s))
                .transpose()?;

            if let Some(addr) = start_addr {
                if addr % sector_size != 0 {
                    return Err(format!(
                        "Start address {:#x} is not aligned to sector size {:#x}",
                        addr, sector_size
                    )
                    .into());
                }
            }
            if let Some(addr) = end_addr {
                if addr % sector_size != 0 {
                    return Err(format!(
                        "End address {:#x} is not aligned to sector size {:#x}",
                        addr, sector_size
                    )
                    .into());
                }
            }

            let mut programmer = make_programmer(sub_matches, part, cancelled.clone())?;
            if let Some(key) = sub_matches.get_one::<String>("key") {
                programmer.set_unlock_key(parse_unlock_key(key)?);
            }
            programmer.set_ignore_part_number(sub_matches.get_flag("ignore_part_number"));
            let eeprom_only = sub_matches.get_flag("eeprom");
            programmer.set_project(Project {
                erase: true,
                eeprom_area: eeprom_only,
                sectors: match (start_addr, end_addr) {
                    _ if eeprom_only => None,
                    (None, None) => None,
                    (start, end) => Some((
                        start.unwrap_or(0) as u32,
                        end.unwrap_or(part.flash_size) as u32,
                    )),
                },
                ..Project::default()
            });
            programmer.erase_init()?;

            if sub_matches.get_flag("eeprom") {
                programmer.erase_eeprom()?;
                programmer.finish()?;
                return Ok(());
            }

            // Use sector-based erase for partial erases, mass erase otherwise
            match (start_addr, end_addr) {
                (Some(start), Some(end)) => {
                    programmer.erase_sectors(start as u32, end as u32)?;
                }
                (Some(start), None) => {
                    programmer.erase_sectors(start as u32, part.flash_size as u32)?;
                }
                (None, Some(end)) => {
                    programmer.erase_sectors(0, end as u32)?;
                }
                (None, None) => match sub_matches.get_one::<String>("erase_mode") {
                    Some(m) => programmer.mass_erase_with_mode(m.parse::<u8>()?)?,
                    None => programmer.mass_erase()?,
                },
            }

            programmer.finish()?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn main() {
    SimpleLogger::new()
        .with_utc_timestamps()
        .with_level(log::LevelFilter::Off)
        .env()
        .init()
        .unwrap();

    // Set up cancellation token for Ctrl+C handling
    let cancelled = Arc::new(AtomicBool::new(false));
    let c = cancelled.clone();
    ctrlc::set_handler(move || {
        c.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    if let Err(e) = run(cancelled) {
        // Don't print cancellation errors - the user already knows they cancelled
        if e.to_string() != "Operation cancelled" {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_key_pads_six_byte_password() {
        assert_eq!(
            parse_unlock_key("a1b2c3d4e5f6").unwrap(),
            [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0, 0]
        );
        assert!(parse_unlock_key("a1b2c3d4e5f6f7f8").is_err()); // full 8-byte key not accepted
        assert!(parse_unlock_key("a1b2c3").is_err()); // too short
    }
}
