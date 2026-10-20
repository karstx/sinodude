//! Driver for the genuine SinoWealth SinoLink USB dongle, 8051 targets.
//!
//! The dongle takes a `0x400`-byte parameter block describing the part and operation, then runs
//! read, write, erase, security and identity commands over its vendor USB interface, driving the
//! target's ICP link (4-wire or single-wire).

use super::{Project, Protection};
use crate::parts::{
    find_parts_by_part_number, hex_string, Part, Region, SecurityRecordFormat, Voltage,
    PROTECTION_PASSWORD_LEN, PROTECTION_PASSWORD_OFFSET, PROTECTION_RECORD_LEN,
};
use indicatif::{ProgressBar, ProgressStyle};
use log::debug;
use nusb::transfer::{
    Buffer, Bulk, ControlIn, ControlOut, ControlType, In, Out, Recipient, TransferError,
};
use nusb::{list_devices, Device, Endpoint, Interface, MaybeFuture};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// WinUSB's default control timeout, which every command the dongle runs synchronously in its
/// control handler has to beat.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait after powering the target rail down before a cold entry. The `0x41` discharge
/// pulse alone (300 ms) does not drain some boards' VDD caps far enough for the target to reset, so
/// the chip is still running and holding the shared JTAG pins when entry fires.
const POWER_SETTLE: Duration = Duration::from_millis(1500);
/// The dongle answers a header command's bulk IN only when the target operation ends; the slowest
/// operation, a ChipType 7 polled erase, takes about 3 s.
const BULK_TIMEOUT: Duration = Duration::from_secs(10);

const SINOWEALTH_VID: u16 = 0x258a;
/// The 8051 firmware image enumerates as 0x5063; 0x5007 is the bootloader.
const PERSONALITY_PID: u16 = 0x5063;
const BOOTLOADER_PID: u16 = 0x5007;
const BULK_IN: u8 = 0x81;
const BULK_OUT: u8 = 0x02;

/// The SinoLink has one socket; requests address it by bit 0 of a socket mask.
const SOCKET_MASK: u8 = 1;
const BLOCK_LEN: usize = 0x400;
/// Bytes compared before the stored block is rewritten; the rest is build time and a mark.
const BLOCK_COMPARED: usize = 0x3f0;
const CHUNK: usize = 0x400;

pub mod req {
    pub const VERSION: u8 = 0x00;
    /// Reboots into the CMSIS-DAP image. Not part of any 8051 operation.
    pub const SWITCH_TO_DAP: u8 = 0x04;
    pub const BLOCK_WRITE: u8 = 0x10;
    pub const BLOCK_READ: u8 = 0x11;
    pub const BLOCK_ERASE: u8 = 0x12;
    pub const BLOCK_RELOAD: u8 = 0x13;
    pub const POWER_STATE: u8 = 0x15;
    pub const SOCKET_STATUS: u8 = 0x16;
    pub const DIAGNOSTICS: u8 = 0x3e;
    /// Reboots into the bootloader and stays there until a firmware image is written.
    pub const ENTER_BOOTLOADER: u8 = 0x3f;
    pub const CONNECT: u8 = 0x40;
    pub const DISCONNECT: u8 = 0x41;
    pub const WRITE: u8 = 0x42;
    pub const READ: u8 = 0x44;
    pub const ERASE: u8 = 0x45;
    pub const KEY: u8 = 0x46;
}

/// `cmd 0x40` sub-commands.
pub mod connect_sub {
    /// Supply, reset and entry with the delay from `wIndex`.
    pub const ENTRY_WITH_DELAY: u8 = 0;
    /// Supply, reset, entry, mode `0x96` and the link check.
    pub const ENTRY: u8 = 1;
    /// Link check only; re-enters ICP when the link state is not `0x96`.
    pub const VERIFY: u8 = 4;
}

/// `cmd 0x41` sub-commands.
pub mod disconnect_sub {
    /// Supply off with a 300 ms discharge pulse and power state 0, unless the target is externally
    /// powered (state 3). No target pin is written.
    pub const POWER_OFF: u8 = 0;
    /// Leave and re-enter ICP; used to retry after a verify mismatch.
    pub const REENTER: u8 = 2;
}

/// Target power state, `cmd 0x15`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Off,
    /// The dongle supplies the target (`P[5]` 1 or 2).
    Dongle(u8),
    /// The dongle saw an external rail above 1900 mV and connected on its own.
    External,
    /// A target rail was already up when the dongle booted. Connects are refused until a
    /// `cmd 0x41` sub 0 clears it.
    PresentAtBoot,
    Other(u8),
}

impl PowerState {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => PowerState::Off,
            1 | 2 => PowerState::Dongle(b),
            3 => PowerState::External,
            5 => PowerState::PresentAtBoot,
            other => PowerState::Other(other),
        }
    }
}

/// Space byte `H[6]` of `0x42` and `0x44`: code (ICP opcodes `0x6E` write, `0x44` read) or the
/// other space (`0xA5` / `0x4A`) that holds the customer block, options, security record and E2.
fn space(region: Region) -> u8 {
    match region {
        Region::Flash => 0,
        Region::Custom => 1,
    }
}

/// Erase type `H[6]` of `cmd 0x45`. The dongle maps it to an ICP erase opcode by ChipType:
/// type 0 is `0xE6` (code sector) or `0x55` (E2 page) by `H[7]`, 1 `0xAA` (`0x4B` on ChipType 7),
/// 2 `0xDA` (`0x3C`), 3 `0x5E`, 4 `0x2D`, 5 `0xC3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseType {
    CodeSector,
    E2Page,
    Chip(u8),
}

impl EraseType {
    fn header(self) -> (u8, u8) {
        match self {
            EraseType::CodeSector => (0, 0),
            EraseType::E2Page => (0, 1),
            EraseType::Chip(t) => (t, 0),
        }
    }
}

/// How the target is powered. Stored in parameter byte 5, which the connect reads to decide which
/// supply to switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    V3_3,
    V5_0,
    /// The board supplies the target; the dongle switches nothing on.
    External,
}

impl Power {
    pub fn param(self) -> u8 {
        match self {
            Power::V3_3 => 1,
            Power::V5_0 => 2,
            Power::External => 3,
        }
    }

    pub fn parse(s: Option<&str>) -> Power {
        match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("5v") | Some("5.0") | Some("5v0") | Some("b") => Power::V5_0,
            Some("external") | Some("ext") | Some("off") | Some("target") => Power::External,
            _ => Power::V3_3,
        }
    }

    /// Refuse a rail the part is not rated for.
    pub fn check(self, part: &Part) -> Result<()> {
        if let Some(v) = self.voltage() {
            if !part.compatible_voltages.contains(&v) {
                return Err(SinoLinkError::UnsupportedVoltage {
                    part: hex_string(&part.part_number),
                    power: self,
                    supported: part
                        .compatible_voltages
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        }
        Ok(())
    }

    fn voltage(self) -> Option<Voltage> {
        match self {
            Power::V3_3 => Some(Voltage::V3_3),
            Power::V5_0 => Some(Voltage::V5_0),
            Power::External => None,
        }
    }
}

impl std::fmt::Display for Power {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Power::V3_3 => write!(f, "3.3 V"),
            Power::V5_0 => write!(f, "5 V"),
            Power::External => write!(f, "external"),
        }
    }
}

/// Target link, parameter byte 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// TCK PB6, TDI PB8, TDO PB7, TMS PB9.
    FourWire,
    /// PB7 only. Offered only for parts with the single-wire `writer_capacity` bit (`0x80000`).
    SingleWire,
}

impl Link {
    pub fn parse(s: Option<&str>) -> Link {
        match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("1wire") | Some("single") | Some("swe") | Some("1") => Link::SingleWire,
            _ => Link::FourWire,
        }
    }
}

/// Settings that reach the parameter block.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub power: Power,
    pub link: Link,
    /// Power-on time, parameter byte 6 (3..27). With "Use Reset Pin" off the connect holds the
    /// lines high for `n - 1` delay units before releasing reset; with it on, reset for
    /// `(n - 1) x 50` ms.
    pub power_on_time: u8,
    /// "Use Reset Pin", parameter byte 9 bit 0. Also makes the host skip the power-state query and
    /// always send a full entry.
    pub use_reset_pin: bool,
    /// The boot (ISP) area toggle (parameter byte `0x14`). Programs the top `isp_size` bytes of the
    /// code image to the ISP region and erases it with the code. Valid only for parts with
    /// `iap == 1`.
    pub boot_rom: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            power: Power::V3_3,
            link: Link::FourWire,
            power_on_time: 3,
            use_reset_pin: false,
            boot_rom: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SinoLinkError {
    #[error("no SinoLink dongle found (looked for USB 258a:5063)")]
    DeviceNotFound,
    #[error("the SinoLink is in its bootloader (258a:5007); it needs a firmware image before it can program a target")]
    InBootloader,
    #[error(
        "the SinoLink runs {0}, not the 8051 firmware; it needs the 8051 firmware image installed"
    )]
    WrongPersonality(&'static str),
    #[error("USB setup failed: {0}")]
    Setup(String),
    #[error("control transfer {request:#04x} failed: {err:?}")]
    Control { request: u8, err: TransferError },
    #[error("bulk transfer failed: {0:?}")]
    Bulk(TransferError),
    #[error("the parameter block did not read back as written after 3 attempts")]
    BlockInstall,
    #[error("a target rail was present when the dongle powered up; it refuses to connect until that is cleared")]
    PoweredAtBoot,
    #[error("unexpected power state {0:#04x}")]
    PowerState(u8),
    #[error("connect failed: {0}")]
    NotConnected(&'static str),
    #[error("{command} failed: {reason} (error {code:#04x})")]
    Failed {
        command: &'static str,
        code: u8,
        reason: &'static str,
    },
    #[error("write at {addr:#x} failed: {reason} (status {code:#04x})")]
    WriteFailed {
        addr: u32,
        code: u8,
        reason: &'static str,
    },
    #[error("{part} does not support {power}; it supports {supported}")]
    UnsupportedVoltage {
        part: String,
        power: Power,
        supported: String,
    },
    #[error("no target power detected; with --power external the board must supply the target")]
    NoExternalPower,
    #[error("{0} does not offer the single-wire link")]
    NoSingleWire(String),
    #[error("part number mismatch: expected {expected}, got {actual}")]
    PartNumberMismatch { expected: String, actual: String },
    #[error("customer key rejected (or the part did not answer the key check)")]
    KeyRejected,
    #[error("dongle replied with {got} bytes, expected at least {want}")]
    ShortReply { want: usize, got: usize },
    #[error("unsupported for this part: {0}")]
    Unsupported(&'static str),
    #[error("protection at offset {offset} cannot be reduced: {current:#04x} is already burnt, {requested:#04x} requested; mass erase first")]
    ProtectionNotReducible {
        offset: usize,
        current: u8,
        requested: u8,
    },
    #[error("cancelled")]
    Cancelled,
}

type Result<T> = std::result::Result<T, SinoLinkError>;

/// The sticky error byte, returned in byte 0 of `cmd 0x40` and `cmd 0x45`.
pub fn decode_error(code: u8) -> &'static str {
    match code {
        0x00 => "ok",
        0x01 => "debug ID read gave 0x0000 or 0xffff",
        0x09 => "link check failed",
        0x0a => "single-wire re-sync failed before a write",
        0x11 => "ChipType 0 write failed",
        0x12 => "ChipType 3 write failed",
        0x22 => "ChipType 1 write failed",
        0xcc => "write failed and its retry failed",
        0x14..=0x19 | 0x20..=0x25 | 0x30 => "single-wire debug transfer timeout",
        0x28 => "erase refused: an earlier error is still set, or the single-wire erase failed",
        0x33 | 0x34 | 0x37 => "single-wire write mismatch",
        0x38 => "single-wire address frame not sent: an earlier error is still set",
        0x99 => "debug mode entry failed",
        0xee => "erase: target never raised TDO",
        0xf3 => "single-wire receive timeout",
        0xf4 => "single-wire link check refused: an earlier error is still set",
        0xf5 => "single-wire sync: no answer from the target",
        0xf6 => "single-wire sync: target pulse outside 32..512 us",
        0xff => "ChipType 0 erase: target never signalled ready",
        _ => "unknown",
    }
}

/// The sub-error byte, returned in byte 0 of `cmd 0x16`.
pub fn decode_sub_error(code: u8) -> &'static str {
    match code {
        0x00 => "ok",
        0x01..=0x04 => "single-wire sync failed",
        0x05 => "link check failed",
        0x08 => "erase not acknowledged",
        0x09 => "single-wire receive: no start or release",
        0x0a => "single-wire receive: no start low",
        0x0b => "single-wire receive: capture short",
        0x0c => "read-back mismatch",
        0x10 => "target did not raise TDO",
        0x50 => "bulk OUT still pending",
        _ => "unknown",
    }
}

/// The 64-byte reply to `cmd 0x00`.
#[derive(Debug, Clone)]
pub struct Version {
    pub raw: Vec<u8>,
}

impl Version {
    pub fn major(&self) -> u8 {
        self.raw[6]
    }
    pub fn minor(&self) -> u8 {
        self.raw[7]
    }
    /// Byte `0x0d`: bit 0 8051, bit 1 Andes, bit 2 ARM.
    pub fn cores(&self) -> u8 {
        self.raw[0x0d]
    }
    pub fn is_bootloader(&self) -> bool {
        self.raw[0x0f] == 0xa5
    }
    pub fn personality(&self) -> &'static str {
        if self.is_bootloader() {
            return "the bootloader";
        }
        if self.raw[0x1f] & 0x08 != 0 {
            return "the CMSIS-DAP image";
        }
        match self.cores() {
            1 => "the 8051 personality",
            2 => "the Andes personality",
            4 => "the ARM personality",
            _ => "an unknown image",
        }
    }
    pub fn unique_id(&self) -> &[u8] {
        &self.raw[0x10..0x1c]
    }
}

pub struct SinoLink {
    _device: Device,
    interface: Interface,
}

impl SinoLink {
    pub fn open() -> Result<Self> {
        let devices: Vec<_> = list_devices()
            .wait()
            .map_err(|e| SinoLinkError::Setup(e.to_string()))?
            .filter(|d| d.vendor_id() == SINOWEALTH_VID)
            .collect();
        let info = match devices.iter().find(|d| d.product_id() == PERSONALITY_PID) {
            Some(d) => d,
            None if devices.iter().any(|d| d.product_id() == BOOTLOADER_PID) => {
                return Err(SinoLinkError::InBootloader)
            }
            None => return Err(SinoLinkError::DeviceNotFound),
        };

        eprintln!(
            "SinoLink: {} {} ({:04x}:{:04x})",
            info.manufacturer_string().unwrap_or("?"),
            info.product_string().unwrap_or("?"),
            info.vendor_id(),
            info.product_id()
        );

        let device = info
            .open()
            .wait()
            .map_err(|e| SinoLinkError::Setup(e.to_string()))?;
        if !matches!(device.active_configuration(), Ok(c) if c.configuration_value() == 1) {
            device
                .set_configuration(1)
                .wait()
                .map_err(|e| SinoLinkError::Setup(e.to_string()))?;
        }
        let interface = device
            .detach_and_claim_interface(0)
            .wait()
            .map_err(|e| SinoLinkError::Setup(e.to_string()))?;

        Ok(Self {
            _device: device,
            interface,
        })
    }

    // --- transport ---------------------------------------------------------

    fn ctrl_in(&self, request: u8, value: u16, index: u16, length: u16) -> Result<Vec<u8>> {
        debug!("ctrl-IN  {request:#04x} val={value:#06x} idx={index:#06x} len={length}");
        let data = self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    length,
                },
                CONTROL_TIMEOUT,
            )
            .wait()
            .map_err(|err| SinoLinkError::Control { request, err })?;
        debug!("ctrl-IN  <= ({}) {:02x?}", data.len(), data);
        Ok(data)
    }

    fn ctrl_out(&self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        debug!("ctrl-OUT {request:#04x} val={value:#06x} idx={index:#06x} data={data:02x?}");
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    data,
                },
                CONTROL_TIMEOUT,
            )
            .wait()
            .map_err(|err| SinoLinkError::Control { request, err })
    }

    /// Byte 0 is the direction of the bulk phase (`0x80` IN), 1 the socket mask, 2..5 the address,
    /// 6 and 7 the command's arguments, 8..13 more arguments, 14..15 the data length.
    fn header(dir_in: bool, mask: u8, addr: u32, args: &[u8], length: u16) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[0] = if dir_in { 0x80 } else { 0x00 };
        h[1] = mask;
        h[2..6].copy_from_slice(&addr.to_le_bytes());
        h[6..6 + args.len()].copy_from_slice(args);
        h[14..16].copy_from_slice(&length.to_le_bytes());
        h
    }

    fn bulk_in(&self, length: usize) -> Result<Vec<u8>> {
        let mut ep: Endpoint<Bulk, In> = self
            .interface
            .endpoint(BULK_IN)
            .map_err(|e| SinoLinkError::Setup(e.to_string()))?;
        let c = ep.transfer_blocking(
            Buffer::new(length.max(1).next_multiple_of(64)),
            BULK_TIMEOUT,
        );
        c.status.map_err(SinoLinkError::Bulk)?;
        debug!(
            "bulk-IN  <= ({}) {:02x?}",
            c.buffer.len(),
            &c.buffer[..c.buffer.len().min(32)]
        );
        Ok(c.buffer[..length.min(c.buffer.len())].to_vec())
    }

    /// Exactly `data.len()` bytes: the dongle arms its bulk endpoint for the header's length and
    /// runs the command when that many bytes have arrived, so padding would sit unread.
    fn bulk_out(&self, data: &[u8]) -> Result<()> {
        let mut ep: Endpoint<Bulk, Out> = self
            .interface
            .endpoint(BULK_OUT)
            .map_err(|e| SinoLinkError::Setup(e.to_string()))?;
        let mut b = Buffer::new(data.len());
        b.extend_from_slice(data);
        let c = ep.transfer_blocking(b, BULK_TIMEOUT);
        c.status.map_err(SinoLinkError::Bulk)
    }

    fn header_in(
        &self,
        request: u8,
        mask: u8,
        addr: u32,
        args: &[u8],
        len: u16,
    ) -> Result<Vec<u8>> {
        self.ctrl_out(request, 0, 0, &Self::header(true, mask, addr, args, len))?;
        self.bulk_in(len as usize)
    }

    fn header_out(&self, request: u8, mask: u8, addr: u32, args: &[u8], data: &[u8]) -> Result<()> {
        self.ctrl_out(
            request,
            0,
            0,
            &Self::header(false, mask, addr, args, data.len() as u16),
        )?;
        self.bulk_out(data)
    }

    /// One vendor control IN, for diagnostics.
    pub fn raw_in(&self, request: u8, value: u16, index: u16, length: u16) -> Result<Vec<u8>> {
        self.ctrl_in(request, value, index, length)
    }

    // --- dongle commands --------------------------------------------------

    pub fn version(&self) -> Result<Version> {
        let raw = self.ctrl_in(req::VERSION, 0, 0, 64)?;
        if raw.len() < 0x20 {
            return Err(SinoLinkError::ShortReply {
                want: 0x20,
                got: raw.len(),
            });
        }
        Ok(Version { raw })
    }

    /// The parameter block stored in the dongle's flash sector 1. Reading it also makes the dongle
    /// reload its RAM copy.
    pub fn read_block(&self) -> Result<Vec<u8>> {
        let b = self.header_in(req::BLOCK_READ, 0, 0, &[0], BLOCK_LEN as u16)?;
        if b.len() < BLOCK_LEN {
            return Err(SinoLinkError::ShortReply {
                want: BLOCK_LEN,
                got: b.len(),
            });
        }
        Ok(b)
    }

    /// Store `block`: skip the write when bytes `0..0x3f0` already match, otherwise up to three
    /// rounds of sector erase, write and read-back. The block write only programs, so it needs the
    /// erase every time.
    pub fn install_block(&self, block: &[u8; BLOCK_LEN]) -> Result<()> {
        let stored = self.read_block()?;
        if stored[..BLOCK_COMPARED] == block[..BLOCK_COMPARED] {
            debug!("parameter block already stored");
            return Ok(());
        }
        for round in 0..3 {
            if round > 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
            self.ctrl_out(req::BLOCK_ERASE, 1, 0, &[])?;
            std::thread::sleep(Duration::from_millis(30));
            self.header_out(req::BLOCK_WRITE, 0, 0, &[0], block)?;
            if self.read_block()?[..] == block[..] {
                return Ok(());
            }
        }
        Err(SinoLinkError::BlockInstall)
    }

    pub fn power_state(&self) -> Result<PowerState> {
        let r = self.ctrl_in(req::POWER_STATE, SOCKET_MASK as u16, 0, 2)?;
        let b = *r
            .first()
            .ok_or(SinoLinkError::ShortReply { want: 1, got: 0 })?;
        Ok(PowerState::from_byte(b))
    }

    /// `cmd 0x16`: the sub-error byte and the address the last command reached.
    pub fn socket_status(&self) -> Result<(u8, u32)> {
        let r = self.ctrl_in(req::SOCKET_STATUS, SOCKET_MASK as u16, 0, 5)?;
        if r.len() < 5 {
            return Err(SinoLinkError::ShortReply {
                want: 5,
                got: r.len(),
            });
        }
        Ok((r[0], u32::from_le_bytes([r[1], r[2], r[3], r[4]])))
    }

    /// `cmd 0x3e`, a diagnostics command not used in normal operation: sub 1 selects a supply (1 or
    /// 2, anything else switches it off with a 1 s discharge pulse) and measures it, 2 reads PB14,
    /// 3 drives GPIOC, 4 drives the target lines, 5 samples PB7 under a pull.
    pub fn diagnostics(&self, sub: u8, arg: u8) -> Result<Vec<u8>> {
        self.ctrl_in(
            req::DIAGNOSTICS,
            u16::from(sub) | (u16::from(arg) << 8),
            0,
            64,
        )
    }

    /// Target supply in millivolts after selecting `supply` (1 3.3 V, 2 5 V, other off).
    pub fn measure_supply(&self, supply: u8) -> Result<u16> {
        let r = self.diagnostics(1, supply)?;
        match (r.get(4), r.get(5)) {
            (Some(&lo), Some(&hi)) => Ok(u16::from_le_bytes([lo, hi])),
            _ => Err(SinoLinkError::ShortReply {
                want: 6,
                got: r.len(),
            }),
        }
    }

    /// `cmd 0x40`. `delay` 0 takes the power-on time from the stored block.
    pub fn connect(&self, sub: u8, delay: u8) -> Result<()> {
        let r = self.ctrl_in(
            req::CONNECT,
            (u16::from(sub) << 8) | SOCKET_MASK as u16,
            u16::from(delay),
            16,
        )?;
        match r.first() {
            Some(0) => Ok(()),
            Some(&code) => Err(SinoLinkError::Failed {
                command: "connect",
                code,
                reason: decode_error(code),
            }),
            None => Err(SinoLinkError::ShortReply { want: 1, got: 0 }),
        }
    }

    /// `cmd 0x41`. Byte 0 of the reply is the error byte for sub 2 and always 0 for sub 0.
    pub fn disconnect(&self, sub: u8) -> Result<u8> {
        let r = self.ctrl_in(
            req::DISCONNECT,
            (u16::from(sub) << 8) | SOCKET_MASK as u16,
            0,
            16,
        )?;
        Ok(r.first().copied().unwrap_or(0))
    }

    /// Connect: with "Use Reset Pin" a full entry every time; otherwise pick by the power state,
    /// because a full entry from a powered state would not see the power-on edge. A state-5 dongle
    /// (rail present at boot) must be cleared with `cmd 0x41` sub 0 first.
    pub fn connect_session(&self, settings: &Settings) -> Result<()> {
        if settings.use_reset_pin {
            return self.connect(connect_sub::ENTRY, 0);
        }
        // An external rail cannot be cycled from here, so verify-attach to it as before.
        if settings.power == Power::External {
            let mut state = self.power_state()?;
            if state == PowerState::Off {
                state = self.wait_power_state(settings.power)?;
            }
            return match state {
                PowerState::External | PowerState::Dongle(_) => {
                    self.connect(connect_sub::VERIFY, 0)
                }
                PowerState::Off => self.connect(connect_sub::ENTRY, 0),
                PowerState::PresentAtBoot => Err(SinoLinkError::PoweredAtBoot),
                PowerState::Other(b) => Err(SinoLinkError::PowerState(b)),
            };
        }
        // Dongle-supplied power: switch the rail on, let the connect's own power-on delay run, and
        // enter ICP. Every operation then runs in this one session and the rail is switched off at
        // finish. Only a target that a previous run left powered has booted its firmware onto the
        // shared JTAG pins (TDO/TMS/TDI/TCK) and refuses entry with link-check error 0x09; recover
        // by cycling the rail and catching it at reset.
        match self.connect(connect_sub::ENTRY, 0) {
            Ok(()) => Ok(()),
            Err(_) => self.cold_entry(),
        }
    }

    /// Recovery when a plain entry failed because the target was left powered: switch the rail off,
    /// wait for the board to discharge, then enter ICP at reset. On a failed entry the rail is left
    /// off so the next attempt still starts cold.
    fn cold_entry(&self) -> Result<()> {
        self.disconnect(disconnect_sub::POWER_OFF)?;
        std::thread::sleep(POWER_SETTLE);
        match self.connect(connect_sub::ENTRY, 0) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = self.disconnect(disconnect_sub::POWER_OFF);
                Err(e)
            }
        }
    }

    /// With an external rail the dongle connects by itself once it sees the rail above 1900 mV, and
    /// reports state 3; it samples the rail about every 0.1 ms, so a second is plenty.
    fn wait_power_state(&self, power: Power) -> Result<PowerState> {
        let start = Instant::now();
        loop {
            let s = self.power_state()?;
            if power != Power::External || s == PowerState::External {
                return Ok(s);
            }
            if start.elapsed() > Duration::from_secs(1) {
                return Err(SinoLinkError::NoExternalPower);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Fail if `cmd 0x16` reports a sub-error. `0x50` means the bulk OUT had not run, which cannot
    /// happen once the transfer returned.
    fn check_status(&self, command: &'static str) -> Result<()> {
        let (code, _) = self.socket_status()?;
        if code == 0 {
            return Ok(());
        }
        Err(SinoLinkError::Failed {
            command,
            code,
            reason: decode_sub_error(code),
        })
    }

    /// `cmd 0x44`. A failing 4-wire link check after the read is not reported here; it sets the
    /// sticky error, which the next connect clears.
    pub fn read(&self, addr: u32, region: Region, length: u16) -> Result<Vec<u8>> {
        let data = self.header_in(req::READ, SOCKET_MASK, addr, &[space(region)], length)?;
        if data.len() < length as usize {
            return Err(SinoLinkError::ShortReply {
                want: length as usize,
                got: data.len(),
            });
        }
        self.check_status("read")?;
        Ok(data)
    }

    /// `cmd 0x42`. The dongle writes when the last OUT packet arrives, retries a failing chunk once
    /// itself, and reports through `cmd 0x16`.
    pub fn write(&self, addr: u32, region: Region, data: &[u8]) -> Result<()> {
        self.header_out(req::WRITE, SOCKET_MASK, addr, &[space(region)], data)?;
        let (code, _) = self.socket_status()?;
        if code == 0 {
            return Ok(());
        }
        Err(SinoLinkError::WriteFailed {
            addr,
            code,
            reason: decode_sub_error(code),
        })
    }

    /// `cmd 0x45`. The reply's byte 0 is the error byte. After any erase but a sector or E2 page
    /// the dongle itself writes 17 zero bytes at the customer block + 10, and one zero byte at the
    /// customer block + `0x100` for types 2 and 3 when the boot area is on.
    pub fn erase(&self, addr: u32, ty: EraseType) -> Result<()> {
        let (t, area) = ty.header();
        let r = self.header_in(req::ERASE, SOCKET_MASK, addr, &[t, area], 16)?;
        match r.first() {
            Some(0) => Ok(()),
            Some(&code) => Err(SinoLinkError::Failed {
                command: "erase",
                code,
                reason: decode_error(code),
            }),
            None => Err(SinoLinkError::ShortReply { want: 1, got: 0 }),
        }
    }

    /// `cmd 0x46`: ICP `4B` with the key, then a `4A` read at the block's key-check address, which
    /// must return `0xC0`. The reply is one byte, 0 on a pass.
    pub fn key(&self, key: &[u8; 8]) -> Result<()> {
        let r = self.header_in(req::KEY, SOCKET_MASK, 0, key, 16)?;
        match r.first() {
            Some(0) => Ok(()),
            Some(_) => Err(SinoLinkError::KeyRejected),
            None => Err(SinoLinkError::ShortReply { want: 1, got: 0 }),
        }
    }
}

/// The part's default code options as eight bytes, words 0 and 1.
fn default_options(part: &Part) -> [u8; 8] {
    let mut options = [0u8; 8];
    let n = part.default_code_options.len().min(8);
    options[..n].copy_from_slice(&part.default_code_options[..n]);
    options
}

/// The chip geometry used to build the parameter block: the part after its load-time capacity
/// patches and option-derived sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChipView {
    pub writer_capacity: u32,
    /// Family code: 1 keeps the customer block in code space, 2 is ChipType 7 without JTAG ID 3213,
    /// 3 is ChipType 8, 0 every other 8051 part.
    pub family: u8,
    /// Code size in bytes.
    pub code_size: u32,
    /// Project code buffer length.
    pub code_len: u32,
    pub eeprom_size: u32,
    pub isp_size: u32,
    pub custom_block: u8,
    pub customer_id: u32,
}

impl ChipView {
    /// `options` matters only for ChipType 7 parts, whose ISP and E2 sizes come from option byte 7.
    pub fn new(part: &Part, options: &[u8; 8]) -> Self {
        // Apply the descriptor's load-time capacity patches.
        let mut wc = part.writer_capacity;
        if part.security.address == 0 {
            wc &= !0x10;
        }
        if part.part_num_address != 0 {
            wc &= !0x1_e400;
        }
        // Bit 16 is a licence setting that is not modelled here.
        wc &= !0x10000;
        if part.chip_type == 7 {
            wc |= if part.jtag_id == 0x3213 {
                0x20_0000
            } else {
                0x10_0000
            };
        }
        // UnitByte is 1 for every 8051 part.
        let mut flash = part.flash_size as u32;
        if part.custom_block == 1 {
            flash -= 0x40;
        }
        let family = if part.chip_type == 8 {
            3
        } else if part.custom_block == 1 {
            1
        } else if part.chip_type == 7 && part.jtag_id != 0x3213 {
            2
        } else {
            0
        };
        let view = ChipView {
            writer_capacity: wc,
            family,
            code_size: flash,
            code_len: flash,
            eeprom_size: part.eeprom_size as u32,
            isp_size: part.isp_size,
            custom_block: part.custom_block,
            customer_id: part.customer_id.address,
        };
        if wc & 0x10_0000 != 0 {
            let size = |nibble: u8, unit: u32| match nibble {
                0..=8 => u32::from(8 - nibble) * unit,
                _ => 0,
            };
            let isp = size(options[7] >> 4, 0x400);
            let e2 = size(options[7] & 0x0f, 0x200);
            let f0 = part.flash_size as u32;
            let cap: u32 = if f0 > 0x10000 {
                0x20000
            } else if f0 > 0x8000 {
                0x10000
            } else {
                0x8000
            };
            let c = f0.min(cap.saturating_sub(e2 + isp));
            return ChipView {
                code_size: c,
                code_len: c,
                eeprom_size: e2,
                isp_size: isp,
                ..view
            };
        }
        let mask_area = if part.iap == 1 && part.isp_size != 0 && !flash.is_multiple_of(0x10000) {
            flash.next_multiple_of(0x10000) - flash - part.isp_size
        } else {
            0
        };
        if mask_area != 0 {
            return ChipView {
                code_len: flash + mask_area + part.isp_size,
                ..view
            };
        }
        view
    }

    /// Customer block: CID, option word 0, security record and S/N.
    pub fn customer_block(&self) -> u32 {
        match self.custom_block {
            0 => 0,
            1 => self.code_size,
            2 => 0x800,
            3 => 0x1000,
            4 => 0x2000,
            6 => self.code_size - 0x20,
            _ => self.customer_id,
        }
    }

    /// Product block, read by the key check.
    pub fn product_block(&self) -> u32 {
        self.customer_id + 0x200
    }

    /// Where the part number sits.
    pub fn part_number_addr(&self) -> u32 {
        if self.family == 1 {
            0
        } else {
            self.product_block() + 9
        }
    }
}

/// CRC-16, polynomial `0x1021`, initial `0xFFFF`, MSB first, no final XOR.
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0xffff, |mut crc: u16, &b| {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
        crc
    })
}

/// CRC-32, polynomial `0x04C11DB7`, initial `0xFFFFFFFF`, MSB first, no final XOR.
pub fn crc32(data: &[u8]) -> u32 {
    data.iter().fold(0xffff_ffff, |mut crc: u32, &b| {
        crc ^= u32::from(b) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
        crc
    })
}

/// Character table for the chip name. A character outside it ends the name.
fn name_code(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'A'..='Z' => Some(c as u8 - b'A' + 10),
        '.' => Some(0x24),
        '\'' => Some(0x25),
        '-' => Some(0x26),
        ' ' => Some(0x27),
        _ => None,
    }
}

fn bcd(v: u32) -> u8 {
    let v = (v % 100) as u8;
    (v / 10) << 4 | (v % 10)
}

/// Parameter block offsets, named for the field each holds. Offsets not listed are never written
/// for an 8051 part and stay 0.
pub mod field {
    /// `78 87`.
    pub const MAGIC: usize = 0x000;
    /// Negated byte sum of `0..0x3f0` minus the counter fields; see [`super::set_block_checksum`].
    pub const CHECKSUM: usize = 0x002;
    pub const CHIP_TYPE: usize = 0x003;
    /// 0 4-wire, 1 single-wire.
    pub const LINK: usize = 0x004;
    /// 1 3.3 V, 2 5 V, 3 external.
    pub const POWER: usize = 0x005;
    /// Power-on time, 3..27.
    pub const POWER_ON_TIME: usize = 0x006;
    /// Power-on time minus 2.
    pub const POWER_ON_TIME_LESS_2: usize = 0x007;
    pub const SECURITY_LEVEL: usize = 0x008;
    /// "Use Reset Pin" flag.
    pub const USE_RESET_PIN: usize = 0x009;
    /// The part's reset-pin setting.
    pub const RESET_PIN: usize = 0x00a;
    /// 5 for every 8051 block. Values 2, 3 and 9 start the CMSIS-DAP image.
    pub const BLOCK_MODE: usize = 0x00b;
    pub const CUSTOM_BLOCK: usize = 0x00e;
    /// Bit `i`: socket `i` enabled. The SinoLink has socket 0 only.
    pub const SOCKETS: usize = 0x00f;
    /// Bit 2 CID programmed, bit 6 CID shown in hex, bit 1 S/N programmed, bit 5 S/N in hex.
    pub const ID_FLAGS: usize = 0x010;
    /// Auto steps: bit 0 security, 1 verify, 2 blank, 4 program, 6 erase, 7 auto-detect; bit 5 is
    /// always set.
    pub const AUTO_STEPS: usize = 0x011;
    /// Bit 0 Agent ID, 2 CRC verify, 4 no LED blink after an error, 5 `ChipConnectOff`.
    pub const RUN_FLAGS: usize = 0x012;
    /// 0 whole chip, 1 selected code sectors, 2 E2 only.
    pub const PROGRAM_MODE: usize = 0x013;
    /// Boot (ISP) area flag; the dongle's post-erase 1-byte write needs it.
    pub const BOOT_AREA: usize = 0x014;
    pub const E2_AREA: usize = 0x015;
    /// The part's IAP (ISP) capability flag.
    pub const IAP: usize = 0x016;
    pub const OTP_AREA: usize = 0x017;
    pub const DSP_SECURITY: usize = 0x018;
    /// Bytes of the protect bitmap in use, two units per byte.
    pub const PROTECT_BYTES: usize = 0x019;
    /// "Ultra Security for Code Memory": record flag bits `0x03`.
    pub const ULTRA_SECURITY: usize = 0x01a;
    /// "SSP Inhibit": record flag bits `0x30`.
    pub const SSP_INHIBIT: usize = 0x01b;
    /// The part's ChipVersion, u32.
    pub const CHIP_VERSION: usize = 0x020;
    /// JTAG ID, u16.
    pub const JTAG_ID: usize = 0x024;
    pub const OPTION_BYTE_COUNT: usize = 0x02f;
    /// Option words 0 and 1, 8 bytes.
    pub const OPTIONS: usize = 0x030;
    /// Project code buffer length, u32.
    pub const CODE_LEN: usize = 0x040;
    /// Length the CRC-32 covers, u32.
    pub const CRC32_LEN: usize = 0x044;
    /// Byte sum of the code buffer, u32.
    pub const CODE_SUM: usize = 0x048;
    pub const CODE_LEN_COPY: usize = 0x054;
    /// CRC-16 of the code buffer, u32.
    pub const CODE_CRC16: usize = 0x058;
    /// CRC-16 of the boot buffer, u32.
    pub const BOOT_CRC16: usize = 0x05c;
    /// E2 size, u32.
    pub const E2_SIZE: usize = 0x064;
    /// Byte sum of the E2 buffer, u32.
    pub const E2_SUM: usize = 0x068;
    /// CRC-32 of the code buffer over [`CRC32_LEN`], u32.
    pub const CODE_CRC32: usize = 0x06c;
    pub const E2_SIZE_COPY: usize = 0x074;
    /// CRC-16 of the E2 buffer, u32.
    pub const E2_CRC16: usize = 0x078;
    /// Sector size, low 16 bits, u32.
    pub const SECTOR_SIZE: usize = 0x080;
    /// Code sectors, u32.
    pub const SECTOR_COUNT: usize = 0x084;
    /// Boot (ISP) block address, u32; `CODE_LEN - ISPSIZE` when the boot area is on.
    pub const BOOT_BLK: usize = 0x090;
    /// ISP size, low 16 bits, u32.
    pub const ISP_SIZE: usize = 0x094;
    /// Chip name length.
    pub const NAME_LEN: usize = 0x0a0;
    /// Chip name, one table code per character, ended by `0xFF`.
    pub const NAME: usize = 0x0a1;
    /// Part number address, u32.
    pub const PART_NUMBER_ADDR: usize = 0x0b0;
    pub const PART_NUMBER_LEN: usize = 0x0b4;
    pub const PART_NUMBER: usize = 0x0b6;
    /// CID length (4), step and start u32.
    pub const CID_LEN: usize = 0x0c0;
    pub const CID_STEP: usize = 0x0c1;
    pub const CID_START: usize = 0x0c2;
    /// S/N length (4), step and start u32.
    pub const SN_LEN: usize = 0x0d0;
    pub const SN_STEP: usize = 0x0d1;
    pub const SN_START: usize = 0x0d2;
    /// First 8 bytes of the code buffer.
    pub const CODE_HEAD: usize = 0x0f0;
    /// Program-count limit, u32.
    pub const PROGRAM_LIMIT: usize = 0x0f8;
    /// Four bits per protect unit: lock, lock, MOVC inhibit (SSP inhibit at SecurityLevel 4),
    /// MOVC inhibit.
    pub const PROTECT_BITMAP: usize = 0x100;
    /// Selected sectors 0..255, one bit each.
    pub const SECTORS_LOW: usize = 0x180;
    /// Selected sectors 256..511.
    pub const SECTORS_HIGH: usize = 0x1a0;
    /// Customer block address, u32; the post-erase writes go relative to it.
    pub const CUSTOMER_BLOCK: usize = 0x204;
    /// Product block address, u32; the key check reads here.
    pub const PRODUCT_BLOCK: usize = 0x208;
    /// The key the host sends with `cmd 0x46`, 8 bytes.
    pub const OLD_PASSWORD: usize = 0x210;
    /// The password a Security step writes, 6 bytes then 2 zeros.
    pub const NEW_PASSWORD: usize = 0x218;
    /// Frequency_Division: the single-wire speed override.
    pub const FREQUENCY_DIVISION: usize = 0x29a;
    /// EraseDelay: the chip-erase wait in 10 ms units, 0 for 300 ms.
    pub const ERASE_DELAY: usize = 0x29b;
    /// Build time, BCD year, month, day, hour, minute, second.
    pub const BUILD_TIME: usize = 0x3f0;
    /// `0x1007`, the block version.
    pub const BUILDER: usize = 0x3f6;
}

/// The `0x400`-byte parameter block for an 8051 part. The dongle reads only [`field::CHIP_TYPE`],
/// [`field::LINK`], [`field::POWER`], the power-on time, reset and mode bytes, `0x0c`, `0x0d`,
/// [`field::CUSTOM_BLOCK`], [`field::BOOT_AREA`], the low byte of [`field::CODE_LEN`], the two
/// block addresses, [`field::FREQUENCY_DIVISION`] and [`field::ERASE_DELAY`]; the rest is
/// bookkeeping that is nevertheless filled in so the stored block matches byte for byte.
///
/// OTP, Agent ID, Security for DSP, CRC verify, the LED and connect-off flags, the program limit
/// and the licence IDs are off or empty; CID and S/N steps are 0 and shown in decimal; the blank,
/// verify and auto-detect steps are off.
pub fn build_block(
    part: &Part,
    name: &str,
    settings: &Settings,
    project: &Project,
    key: &[u8; 8],
    now: chrono::NaiveDateTime,
) -> [u8; BLOCK_LEN] {
    use chrono::{Datelike, Timelike};
    use field::*;

    let mut options = default_options(part);
    if let Some(word0) = &project.code_options {
        let m = word0.len().min(4);
        options[..m].copy_from_slice(&word0[..m]);
    }
    let chip = ChipView::new(part, &options);

    let mut code = vec![0u8; chip.code_len as usize];
    if let Some(flash) = &project.flash {
        let m = flash.len().min(code.len());
        code[..m].copy_from_slice(&flash[..m]);
    }
    // A part with no E2 has no E2 buffer, so its sum and CRC are 0.
    let eeprom = (chip.eeprom_size > 0).then(|| {
        let mut e = vec![0u8; chip.eeprom_size as usize];
        if let Some(src) = &project.eeprom {
            let m = src.len().min(e.len());
            e[..m].copy_from_slice(&src[..m]);
        }
        e
    });
    let sum = |d: &[u8]| d.iter().map(|&v| u32::from(v)).sum::<u32>();

    let mut b = [0u8; BLOCK_LEN];
    let put32 = |b: &mut [u8; BLOCK_LEN], at: usize, v: u32| {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes())
    };

    b[MAGIC..MAGIC + 2].copy_from_slice(&0x8778u16.to_le_bytes());
    b[CODE_HEAD..CODE_HEAD + 8].copy_from_slice(&code[..8]);
    b[BLOCK_MODE] = 5;

    if part.part_number == [0; 5] {
        // An empty PartNumber: length 2, then CPUType and CPUIndex, which no 8051 descriptor sets.
        b[PART_NUMBER_LEN] = 2;
    } else {
        b[PART_NUMBER_LEN] = part.part_number.len() as u8;
        b[PART_NUMBER..PART_NUMBER + 5].copy_from_slice(&part.part_number);
    }
    put32(&mut b, PART_NUMBER_ADDR, chip.part_number_addr());
    put32(&mut b, CUSTOMER_BLOCK, chip.customer_block());
    put32(&mut b, PRODUCT_BLOCK, chip.product_block());

    put32(&mut b, CODE_SUM, sum(&code));
    put32(&mut b, CODE_CRC16, u32::from(crc16(&code)));
    put32(
        &mut b,
        E2_CRC16,
        eeprom.as_deref().map_or(0, |e| u32::from(crc16(e))),
    );
    put32(&mut b, E2_SUM, eeprom.as_deref().map_or(0, sum));
    // With the boot area off there is no boot buffer, so its CRC-16 is 0. With it on, the buffer is
    // the ISP tail (the top `isp_size` bytes of the code image).
    let boot_crc = if settings.boot_rom {
        let start = (chip.code_len - chip.isp_size) as usize;
        u32::from(crc16(&code[start..]))
    } else {
        0
    };
    put32(&mut b, BOOT_CRC16, boot_crc);

    // The name goes in after the part-number address, so a 16-character name overwrites its low
    // bytes.
    let upper: Vec<char> = name.to_ascii_uppercase().chars().collect();
    b[NAME_LEN] = upper.len() as u8;
    let mut at = NAME;
    for &c in upper.iter().take(16) {
        let Some(code) = name_code(c) else { break };
        b[at] = code;
        at += 1;
    }
    b[at] = 0xff;

    if chip.writer_capacity & 0x8000 != 0 {
        b[CID_LEN] = 4;
        b[ID_FLAGS] |= 0x04;
        b[CID_STEP] = 0;
        b[CID_START..CID_START + 4].copy_from_slice(&project.customer_id.unwrap_or([0; 4]));
    }
    if chip.writer_capacity & 0x4000 != 0 {
        b[SN_START..SN_START + 4].copy_from_slice(&project.serial_number.unwrap_or([0; 4]));
        b[SN_LEN] = 4;
        b[SN_STEP] = 0;
        b[ID_FLAGS] |= 0x02;
    }

    b[AUTO_STEPS] = 0x20
        | if project.erase { 0x40 } else { 0 }
        | if project.program { 0x10 } else { 0 }
        | if project.security { 0x01 } else { 0 };
    put32(&mut b, PROGRAM_LIMIT, 0);
    b[RUN_FLAGS] = 0;
    b[BOOT_AREA] = u8::from(settings.boot_rom);
    b[OTP_AREA] = 0;
    b[DSP_SECURITY] = 0;
    b[SOCKETS] = 1;
    b[PROGRAM_MODE] = match (
        &project.sectors,
        project.flash.is_some(),
        project.eeprom_area,
    ) {
        (Some(_), _, _) => 1,
        (None, false, true) => 2,
        _ => 0,
    };
    b[E2_AREA] = u8::from(project.eeprom_area);
    b[CUSTOM_BLOCK] = part.custom_block;
    b[RESET_PIN] = part.reset_pin;
    b[USE_RESET_PIN] = u8::from(settings.use_reset_pin);
    b[CHIP_TYPE] = part.chip_type;
    // The integer JTAG ID reads 161B back as 161A.
    let jtag = if part.jtag_id == 0x161b {
        0x161a
    } else {
        part.jtag_id
    };
    b[JTAG_ID..JTAG_ID + 2].copy_from_slice(&jtag.to_le_bytes());
    put32(&mut b, SECTOR_SIZE, (part.sector_size as u32) & 0xffff);
    let sectors = chip.code_size.div_ceil(part.sector_size as u32);
    put32(&mut b, SECTOR_COUNT, sectors);
    put32(
        &mut b,
        ISP_SIZE,
        if settings.boot_rom {
            chip.isp_size
        } else {
            chip.isp_size & 0xffff
        },
    );
    if settings.boot_rom {
        put32(&mut b, BOOT_BLK, chip.code_len - chip.isp_size);
    }
    put32(&mut b, E2_SIZE, chip.eeprom_size);
    let crc_base = if settings.boot_rom {
        chip.code_len - chip.isp_size
    } else {
        chip.code_len
    };
    put32(&mut b, CODE_LEN, chip.code_len);
    put32(&mut b, CRC32_LEN, crc_base);
    put32(&mut b, CODE_LEN_COPY, chip.code_len);
    put32(&mut b, E2_SIZE_COPY, chip.eeprom_size);
    b[SECURITY_LEVEL] = part.security_level;
    b[POWER] = settings.power.param();
    b[POWER_ON_TIME] = settings.power_on_time;
    b[POWER_ON_TIME_LESS_2] = settings.power_on_time.wrapping_sub(2);

    if let Some((start, end)) = project.sectors {
        let size = part.sector_size as u32;
        for k in start / size..end.div_ceil(size) {
            let (base, bit) = if k < 256 {
                (SECTORS_LOW, k)
            } else {
                (SECTORS_HIGH, k - 256)
            };
            b[base + (bit / 8) as usize] |= 1 << (bit % 8);
        }
    }
    b[OLD_PASSWORD..OLD_PASSWORD + 8].copy_from_slice(key);
    if let Some(p) = &project.new_password {
        b[NEW_PASSWORD..NEW_PASSWORD + 6].copy_from_slice(p);
    }
    b[ERASE_DELAY] = part.erase_delay;

    b[IAP] = part.iap;
    b[LINK] = match settings.link {
        Link::FourWire => 0,
        Link::SingleWire => 1,
    };
    put32(&mut b, CHIP_VERSION, part.chip_version & 0xffff);
    if part.option_byte_count > 0 {
        b[OPTION_BYTE_COUNT] = part.option_byte_count as u8;
        b[OPTIONS..OPTIONS + 8].copy_from_slice(&options);
    }
    let sectors_per_unit = if part.security_level == 3 {
        4
    } else {
        match part.chip_type {
            0 | 1 => 1,
            7 => 8,
            _ => 2,
        }
    };
    let units = sectors.div_ceil(sectors_per_unit) as usize;
    for k in 0..units {
        let lock = project.read_protect.get(k).copied().unwrap_or(false);
        let inhibit = project.write_protect.get(k).copied().unwrap_or(false);
        let mut set = |bit: usize, on: bool| {
            if on {
                b[PROTECT_BITMAP + bit / 8] |= 1 << (bit % 8);
            }
        };
        set(4 * k, lock);
        set(4 * k + 1, lock);
        set(4 * k + 2, inhibit && part.security_level != 4);
        set(4 * k + 3, inhibit);
    }
    b[PROTECT_BYTES] = units.div_ceil(2) as u8;
    let any_inhibit = project.write_protect.iter().any(|&w| w);
    b[ULTRA_SECURITY] = u8::from(any_inhibit);
    b[SSP_INHIBIT] = u8::from(any_inhibit);
    b[FREQUENCY_DIVISION] = part.frequency_division;

    // The CRC-32 range ends at the 64-byte line after the last non-zero code byte past byte 0.
    let mut crc_len = crc_base as usize;
    if let Some(last) = (1..crc_len).rev().find(|&i| code[i] != 0) {
        crc_len = (last / 0x40 + 1) * 0x40;
        put32(&mut b, CRC32_LEN, crc_len as u32);
    }
    put32(&mut b, CODE_CRC32, crc32(&code[..crc_len.min(code.len())]));

    let t = [
        now.year() as u32,
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    ];
    for (i, v) in t.into_iter().enumerate() {
        b[BUILD_TIME + i] = bcd(v);
    }
    b[BUILDER..BUILDER + 2].copy_from_slice(&0x1007u16.to_le_bytes());
    set_block_checksum(&mut b);
    b
}

/// Two's complement of the sum of `[0x00..=0x3ef]`, skipping the checksum byte itself and the
/// three counter fields the dongle may refresh.
pub fn set_block_checksum(b: &mut [u8; BLOCK_LEN]) {
    let excluded = |i: usize| {
        i == 0x02
            || (0xc2..=0xc5).contains(&i)
            || (0xd2..=0xd5).contains(&i)
            || (0x246..=0x24d).contains(&i)
    };
    let sum: u32 = (0..BLOCK_COMPARED)
        .filter(|&i| !excluded(i))
        .map(|i| u32::from(b[i]))
        .sum();
    b[0x02] = sum.wrapping_neg() as u8;
}

/// The family-2 whole-chip erase type from the current option word 1 (`have`, as read from the
/// part) and the one about to be written (`want`). The top byte holds the ISP size (high nibble)
/// and E2 size (low nibble); a difference widens the erase: type 4 (`0x2D`) for a low-nibble
/// difference, 5 (`0xC3`, code, ISP and E2) for a high-nibble one, else type 1. The Boot Rom area
/// ORs into the high-nibble test, raising 1 to 2 and 4 to 5. A read-protected part answers all
/// `0xFF`: the current partition cannot be read, so there is nothing to widen against and the base
/// type is used (the target partition still comes from the option word written into the block).
fn family2_erase_type(have: &[u8], want: &[u8; 4], boot: bool) -> u8 {
    if have.iter().all(|&b| b == 0xff) {
        return 1 + u8::from(boot);
    }
    let diff = have[3] ^ want[3];
    let h = diff & 0xf0 != 0 || boot;
    let l = diff & 0xf0 != 0 || diff & 0x0f != 0;
    if h {
        if l {
            5
        } else {
            2
        }
    } else if l {
        4
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// CLI-facing backend
// ---------------------------------------------------------------------------

const EEPROM_PAGE_SIZE: usize = 256;
const CUSTOM_FIELDS_REGION: usize = 0x40;
/// A verify chunk is re-read after re-entering ICP, at most five reads in all.
const VERIFY_READS: usize = 5;

/// The [`crate::programmer::Programmer`] backend for the SinoLink dongle.
pub struct SinoLinkProgrammer {
    link: SinoLink,
    part: &'static Part,
    name: &'static str,
    settings: Settings,
    cancelled: Arc<AtomicBool>,
    unlock_key: Option<[u8; 8]>,
    ignore_part_number: bool,
    stored_custom: Option<Vec<u8>>,
    connected: bool,
    project: Project,
    chip: ChipView,
}

impl SinoLinkProgrammer {
    pub fn new(
        part: &'static Part,
        name: &'static str,
        cancelled: Arc<AtomicBool>,
        settings: Settings,
    ) -> Result<Self> {
        settings.power.check(part)?;
        if settings.link == Link::SingleWire && part.writer_capacity & 0x80000 == 0 {
            return Err(SinoLinkError::NoSingleWire(name.to_uppercase()));
        }
        if part.chip_type >= 0x20 {
            return Err(SinoLinkError::Unsupported(
                "only 8051 parts are driven through the SinoLink so far",
            ));
        }
        let link = SinoLink::open()?;
        Ok(Self {
            link,
            part,
            name,
            settings,
            cancelled,
            unlock_key: None,
            ignore_part_number: false,
            stored_custom: None,
            connected: false,
            project: Project::default(),
            chip: ChipView::new(part, &default_options(part)),
        })
    }

    pub fn set_unlock_key(&mut self, key: [u8; 8]) {
        self.unlock_key = Some(key);
    }

    pub fn set_ignore_part_number(&mut self, ignore: bool) {
        self.ignore_part_number = ignore;
    }

    /// What the operation is about to do; the whole project is described in the parameter block,
    /// so it has to be known before the session opens.
    pub fn set_project(&mut self, project: Project) {
        let mut options = default_options(self.part);
        if let Some(word0) = &project.code_options {
            let m = word0.len().min(4);
            options[..m].copy_from_slice(&word0[..m]);
        }
        self.chip = ChipView::new(self.part, &options);
        self.project = project;
    }

    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(SinoLinkError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Firmware check, connect, customer key and identity read, in that order.
    fn session(&mut self) -> Result<()> {
        if self.settings.boot_rom && (self.part.iap != 1 || self.part.isp_size == 0) {
            return Err(SinoLinkError::Unsupported("this part has no boot/ISP area"));
        }
        let version = self.link.version()?;
        if version.cores() & 1 == 0 || version.is_bootloader() {
            return Err(SinoLinkError::WrongPersonality(version.personality()));
        }
        debug!(
            "SinoLink firmware V{:x}.{:02x}",
            version.major(),
            version.minor()
        );
        let block = build_block(
            self.part,
            self.name,
            &self.settings,
            &self.project,
            &self.unlock_key.unwrap_or([0u8; 8]),
            chrono::Local::now().naive_local(),
        );
        self.link.install_block(&block)?;

        self.link.connect_session(&self.settings)?;
        self.connected = true;
        eprintln!(
            "Connected ({}, {})",
            self.settings.power,
            match self.settings.link {
                Link::FourWire => "4-wire",
                Link::SingleWire => "single-wire",
            }
        );

        // Unlock a protected part only when the user supplied a key: the old password opens a
        // locked chip before erase or program, and a blank or freshly erased part needs no unlock.
        // A rejected key does not abort; the later operation on a still-locked part reports it. The
        // read, write and erase frames themselves need no key.
        if let Some(key) = self.unlock_key {
            if let Err(SinoLinkError::KeyRejected) = self.link.key(&key) {
                eprintln!("Unlock key rejected: the part may be locked or the key is wrong");
            }
        }

        self.verify_part_number()?;
        self.stored_custom = self
            .link
            .read(
                self.chip.customer_block(),
                self.customer_region(),
                CUSTOM_FIELDS_REGION as u16,
            )
            .ok();
        Ok(())
    }

    /// Family 1 keeps its customer block in code space.
    fn customer_region(&self) -> Region {
        if self.chip.family == 1 {
            Region::Flash
        } else {
            Region::Custom
        }
    }

    /// Re-check the link before a batch of writes. A read's own link check reports nothing when it
    /// fails, but leaves an error that makes every later write return without touching the target
    /// while `cmd 0x16` still says 0; any `cmd 0x40` clears it.
    fn relink(&self) -> Result<()> {
        self.link.connect(connect_sub::VERIFY, 0)
    }

    /// Identity read: `0x40` bytes of the other space at the key-check address + 9, the first 5 of
    /// which must be the part's PartNumber.
    fn verify_part_number(&mut self) -> Result<()> {
        if self.chip.family == 1 {
            return Ok(());
        }
        let data = self
            .link
            .read(self.chip.part_number_addr(), Region::Custom, 0x40)?;
        let actual = &data[..5];
        eprintln!("Target part number: {}", hex_string(actual));
        if actual == self.part.part_number {
            return Ok(());
        }
        // A locked or blank part answers the identity read with all 0x00 or 0xFF: there is no
        // number to check, so skip rather than fail.
        if actual.iter().all(|&b| b == 0x00) || actual.iter().all(|&b| b == 0xff) {
            eprintln!("No part number read back (locked or blank); skipping the identity check");
            return Ok(());
        }
        if self.ignore_part_number {
            eprintln!("Part number mismatch ignored");
            return Ok(());
        }
        let matching = find_parts_by_part_number(actual.try_into().unwrap());
        if !matching.is_empty() {
            eprintln!(
                "Parts matching {}: {}",
                hex_string(actual),
                matching.join(", ")
            );
        }
        Err(SinoLinkError::PartNumberMismatch {
            expected: hex_string(&self.part.part_number),
            actual: hex_string(actual),
        })
    }

    pub fn read_init(&mut self) -> Result<()> {
        self.session()
    }

    pub fn write_init(&mut self) -> Result<()> {
        self.session()
    }

    pub fn erase_init(&mut self) -> Result<()> {
        self.session()
    }

    fn progress(&self, len: u64, what: &str) -> ProgressBar {
        let bar = ProgressBar::new(len);
        bar.set_style(
            ProgressStyle::with_template(&format!(
                "{what} {{bar:40}} {{bytes}}/{{total_bytes}} ({{eta}})"
            ))
            .unwrap(),
        );
        bar
    }

    pub fn read_region(
        &self,
        region: Region,
        addr: u32,
        len: usize,
        what: &str,
    ) -> Result<Vec<u8>> {
        let bar = self.progress(len as u64, what);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            self.check_cancelled()?;
            let n = (len - out.len()).min(CHUNK);
            out.extend_from_slice(&self.link.read(addr + out.len() as u32, region, n as u16)?);
            bar.set_position(out.len() as u64);
        }
        bar.finish_and_clear();
        Ok(out)
    }

    pub fn write_region(
        &mut self,
        region: Region,
        addr: u32,
        data: &[u8],
        what: &str,
    ) -> Result<()> {
        self.relink()?;
        let bar = self.progress(data.len() as u64, what);
        for (i, chunk) in data.chunks(CHUNK).enumerate() {
            self.check_cancelled()?;
            if let Err(e) = self.link.write(addr + (i * CHUNK) as u32, region, chunk) {
                bar.finish_and_clear();
                return Err(e);
            }
            bar.set_position((i * CHUNK + chunk.len()) as u64);
        }
        bar.finish_and_clear();
        Ok(())
    }

    /// Read `len` bytes and compare with `expected`, re-entering ICP and re-reading a mismatching
    /// chunk on a mismatch.
    pub fn verify_region(&self, region: Region, addr: u32, expected: &[u8]) -> Result<bool> {
        for (i, want) in expected.chunks(0x200).enumerate() {
            let at = addr + (i * 0x200) as u32;
            let mut ok = false;
            for attempt in 0..VERIFY_READS {
                if attempt > 0 {
                    self.link.disconnect(disconnect_sub::REENTER)?;
                }
                if self.link.read(at, region, want.len() as u16)? == want {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn read_flash(&mut self) -> Result<Vec<u8>> {
        // The whole image, boot area included, is readable from the code space: the boot/ISP tail is
        // written there as part of the main program (it is only trimmed when `isp_size >= 0x10000`,
        // which no supported part reaches). The separate space-1 boot copy is write only.
        self.read_region(Region::Flash, 0, self.part.flash_size, "flash")
    }

    pub fn read_eeprom(&mut self) -> Result<Vec<u8>> {
        if self.part.eeprom_size == 0 {
            return Err(SinoLinkError::Unsupported("this part has no data EEPROM"));
        }
        self.read_region(Region::Custom, 0, self.part.eeprom_size, "eeprom")
    }

    /// One E2 page erase (type 0, area 1, ICP `0x55`) per 256 bytes.
    pub fn erase_eeprom(&mut self) -> Result<()> {
        if self.part.eeprom_size == 0 {
            return Err(SinoLinkError::Unsupported("this part has no data EEPROM"));
        }
        let pages = self.part.eeprom_size.div_ceil(EEPROM_PAGE_SIZE);
        eprintln!("Erasing data EEPROM: {pages} page(s) of {EEPROM_PAGE_SIZE} bytes");
        self.relink()?;
        for p in 0..pages {
            self.check_cancelled()?;
            self.link
                .erase((p * EEPROM_PAGE_SIZE) as u32, EraseType::E2Page)?;
        }
        Ok(())
    }

    pub fn write_eeprom(&mut self, data: &[u8]) -> Result<()> {
        if self.part.eeprom_size == 0 {
            return Err(SinoLinkError::Unsupported("this part has no data EEPROM"));
        }
        self.erase_eeprom()?;
        let n = self.part.eeprom_size.min(data.len());
        self.write_region(Region::Custom, 0, &data[..n], "eeprom")
    }

    /// Option word 1 for a fresh project: the part's default option bytes 4..8.
    fn option_word_1(&self) -> Option<[u8; 4]> {
        if self.part.option_byte_count <= 4 {
            return None;
        }
        Some(default_options(self.part)[4..8].try_into().unwrap())
    }

    /// The whole-chip erase type. Family 2 reads option word 1 back and widens the erase when its
    /// top byte (ISP and E2 sizes) differs from the one to be written: type 4 (`0x2D`) for
    /// a low-nibble difference, 5 (`0xC3`, code, ISP and E2) for a high-nibble one. Every other
    /// family uses type 1. The Boot Rom area raises type 1 to 2 (code and boot) and, for family 2,
    /// ORs into the high-nibble test (`type = H ? (L ? 5 : 2) : (L ? 4 : 1)`, `H = hi | boot`).
    fn whole_chip_erase_type(&self) -> Result<u8> {
        let boot = self.settings.boot_rom;
        if self.chip.family != 2 {
            return Ok(1 + u8::from(boot));
        }
        let Some(want) = self.option_word_1() else {
            return Ok(1 + u8::from(boot));
        };
        let have = self
            .link
            .read(self.chip.customer_block() + 0x100, Region::Custom, 4)?;
        Ok(family2_erase_type(&have, &want, boot))
    }

    fn erase_with_type(&mut self, ty: u8) -> Result<()> {
        eprintln!("Erasing (type {ty})");
        let t = Instant::now();
        self.relink()?;
        self.link.erase(0, EraseType::Chip(ty))?;
        if let Err(e @ SinoLinkError::Failed { code: 0x0c, .. }) = self.link.check_status("erase") {
            return Err(e);
        }
        if self.chip.family == 2 {
            if let Some(w) = self.option_word_1() {
                eprintln!("Writing option word 1 {:02x?}", w);
                self.link
                    .write(self.chip.customer_block() + 0x100, Region::Custom, &w)?;
            }
        }
        eprintln!("Erase complete in {:.2?}", t.elapsed());
        Ok(())
    }

    pub fn mass_erase(&mut self) -> Result<()> {
        let ty = self.whole_chip_erase_type()?;
        self.erase_with_type(ty)
    }

    /// Erase with an explicit `cmd 0x45` type: 1 code (`0xAA`, `0x4B` on ChipType 7), 2 code and
    /// boot (`0xDA` / `0x3C`), 3 `0x5E`, 4 `0x2D`, 5 code, ISP and E2 (`0xC3`).
    pub fn mass_erase_with_mode(&mut self, mode: u8) -> Result<()> {
        if !(1..=5).contains(&mode) {
            return Err(SinoLinkError::Unsupported("erase types are 1 to 5"));
        }
        self.erase_with_type(mode)
    }

    pub fn erase_sectors(&mut self, start_addr: u32, end_addr: u32) -> Result<()> {
        let size = self.part.sector_size as u32;
        let first = start_addr / size * size;
        let count = end_addr.saturating_sub(first).div_ceil(size);
        eprintln!("Erasing {count} sector(s) of {size} bytes from {first:#x}");
        self.relink()?;
        for i in 0..count {
            self.check_cancelled()?;
            self.link.erase(first + i * size, EraseType::CodeSector)?;
        }
        Ok(())
    }

    pub fn write_flash(&mut self, firmware: &[u8]) -> Result<()> {
        let n = self.part.flash_size.min(firmware.len());
        self.write_region(Region::Flash, 0, &firmware[..n], "flash")?;
        if self.settings.boot_rom {
            self.write_boot_tail(firmware)?;
        }
        Ok(())
    }

    /// The boot (ISP) tail: the top `isp_size` bytes of the code image, programmed to space 1 at
    /// the boot-block address. Sent only in whole-chip mode and never read back (the boot area is
    /// encrypted and not verified), so there is no verify pass here either.
    fn write_boot_tail(&mut self, firmware: &[u8]) -> Result<()> {
        let isp = self.chip.isp_size as usize;
        let bootblk = (self.chip.code_len - self.chip.isp_size) as usize;
        let mut tail = vec![0u8; isp];
        if firmware.len() > bootblk {
            let avail = (firmware.len() - bootblk).min(isp);
            tail[..avail].copy_from_slice(&firmware[bootblk..bootblk + avail]);
        }
        self.write_region(Region::Custom, bootblk as u32, &tail, "boot")
    }

    pub fn write_flash_range(&mut self, firmware: &[u8], start: usize, end: usize) -> Result<()> {
        let limit = self.part.flash_size.min(firmware.len());
        let start = start.min(limit);
        let end = end.min(limit);
        if end <= start {
            return Ok(());
        }
        self.write_region(Region::Flash, start as u32, &firmware[start..end], "flash")
    }

    /// The `0x40`-byte customer block written in one `0x42`: CID at 0, operation number at 4,
    /// option word 0 at 6, security record at `0x0a`, S/N at `0x3c`.
    pub fn write_custom_fields(
        &mut self,
        customer_id: Option<&[u8; 4]>,
        operation_number: Option<&[u8; 2]>,
        customer_option: Option<&[u8]>,
        security: Option<&[u8]>,
        serial_number: Option<&[u8; 4]>,
        use_stored_defaults: bool,
    ) -> Result<()> {
        let base = self.part.customer_id.address;
        let stored = self.stored_custom.clone();
        let at = |field_addr: u32| (field_addr - base) as usize;
        let mut buf = [0u8; CUSTOM_FIELDS_REGION];

        let stored_slice = |off: usize, len: usize| -> Option<Vec<u8>> {
            if !use_stored_defaults {
                return None;
            }
            stored
                .as_ref()
                .filter(|s| s.len() >= off + len)
                .map(|s| s[off..off + len].to_vec())
        };

        for (off, len, given) in [
            (0usize, 4usize, customer_id.map(|v| v.to_vec())),
            (
                at(self.part.operation_number.address),
                2,
                operation_number.map(|v| v.to_vec()),
            ),
            (
                at(self.part.serial_number.address),
                4,
                serial_number.map(|v| v.to_vec()),
            ),
        ] {
            if let Some(v) = given.or_else(|| stored_slice(off, len)) {
                if off + len <= CUSTOM_FIELDS_REGION {
                    buf[off..off + len].copy_from_slice(&v[..len]);
                }
            }
        }

        // Only option word 0 lives here; word 1 sits at the customer block + 0x100.
        let opt_off = at(self.part.customer_option.address);
        if let Some(v) = customer_option
            .map(|v| v.to_vec())
            .or_else(|| stored_slice(opt_off, 4))
        {
            let n = v.len().min(4).min(CUSTOM_FIELDS_REGION - opt_off);
            buf[opt_off..opt_off + n].copy_from_slice(&v[..n]);
        }

        if let Some(v) = security {
            let off = at(self.part.security.address);
            let len = v.len().min(CUSTOM_FIELDS_REGION - off);
            buf[off..off + len].copy_from_slice(&v[..len]);
        }

        eprintln!("Writing custom fields ({CUSTOM_FIELDS_REGION} bytes) at {base:#x}");
        let region = self.customer_region();
        self.write_region(region, base, &buf, "custom")
    }

    pub fn read_protection(&mut self) -> Result<Protection> {
        if self.part.security_record_format != SecurityRecordFormat::Record19 {
            return Err(SinoLinkError::Unsupported(
                "this part has no Record19 security record",
            ));
        }
        if self.part.protection_exceeds_record() {
            return Err(SinoLinkError::Unsupported(
                "this part needs more protection groups than a 25-byte record can hold",
            ));
        }
        let raw = self.read_region(
            Region::Custom,
            self.part.security.address,
            PROTECTION_RECORD_LEN,
            "security",
        )?;
        let (read, write) = self.part.decode_protection_record(&raw);
        Ok(Protection {
            read,
            write,
            record: raw,
        })
    }

    /// The security step: one `0x19`-byte `0x42` at the security-record address.
    pub fn apply_protection(
        &mut self,
        read_protect: &[bool],
        write_protect: &[bool],
        new_password: Option<&[u8; PROTECTION_PASSWORD_LEN]>,
    ) -> Result<()> {
        if self.part.security_record_format != SecurityRecordFormat::Record19 {
            return Err(SinoLinkError::Unsupported(
                "this part has no Record19 security record",
            ));
        }
        if self.part.protection_exceeds_record() {
            return Err(SinoLinkError::Unsupported(
                "this part needs more protection groups than a 25-byte record can hold",
            ));
        }
        let existing = self
            .read_region(
                Region::Custom,
                self.part.security.address,
                PROTECTION_RECORD_LEN,
                "security",
            )
            .unwrap_or_else(|_| vec![0u8; PROTECTION_RECORD_LEN]);
        let mut password = [0u8; PROTECTION_PASSWORD_LEN];
        if existing.len() >= PROTECTION_PASSWORD_OFFSET + PROTECTION_PASSWORD_LEN {
            password.copy_from_slice(
                &existing[PROTECTION_PASSWORD_OFFSET
                    ..PROTECTION_PASSWORD_OFFSET + PROTECTION_PASSWORD_LEN],
            );
        }
        if let Some(p) = new_password {
            password = *p;
        }
        let record = self
            .part
            .build_protection_record(read_protect, write_protect, &password);

        // Erased flash reads 0x00 here and programming only sets bits, so a bit already burnt
        // cannot be cleared without a mass erase.
        for (i, (&want, &have)) in record.iter().zip(existing.iter()).enumerate() {
            if have & !want != 0 {
                return Err(SinoLinkError::ProtectionNotReducible {
                    offset: i,
                    current: have,
                    requested: want,
                });
            }
        }
        eprintln!(
            "Writing protection record ({} bytes) at {:#x}",
            PROTECTION_RECORD_LEN, self.part.security.address
        );
        self.write_region(
            Region::Custom,
            self.part.security.address,
            &record,
            "security",
        )
    }

    /// Disconnect: supply off with a discharge pulse; nothing changes on an externally powered
    /// target.
    pub fn finish(&mut self) -> Result<()> {
        if self.connected {
            self.connected = false;
            self.link.disconnect(disconnect_sub::POWER_OFF)?;
        }
        Ok(())
    }
}

impl Drop for SinoLinkProgrammer {
    fn drop(&mut self) {
        if self.connected {
            let _ = self.link.disconnect(disconnect_sub::POWER_OFF);
        }
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use hex_literal::hex;

    /// A reference SH68F90A parameter block, power-on times 3 and 4.
    const BLOCK_3V3_T3: [u8; 1024] = hex!(
        "78877a0700010301040000050000030106f20000000000000008000000000000"
        "00000000000000000000000000000008a4e063c00f0000880000000000000000"
        "0000010040ff0000c04a64000000000000000000000001008658000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0002000080000000000000000000000000000000000000000000000000000000"
        "081c1106080f09000aff00000000000009120000050068f90a00000000000000"
        "0400000000000000000000000000000004000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000100000001200000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000024011514321605500000000000000000"
    );
    const BLOCK_5V_T4: [u8; 1024] = hex!(
        "7887bd0700020402040000050000030106200000000000000008000000000000"
        "00000000000000000000000000000008a4e063c00f0000880000000000000000"
        "0000010040ff0000fd8f3600000000000000000000000100b363000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0002000080000000000000000000000000000000000000000000000000000000"
        "081c1106080f09000aff00000000000009120000050068f90a00000000000000"
        "0400000000000000000000000000000004000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000100000001200000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000023030820360705500000000000000000"
    );

    /// Every offset the dongle reads from the block.
    const FIRMWARE_READ: &[usize] = &[
        0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x14, 0x40, 0x204, 0x205,
        0x206, 0x207, 0x208, 0x209, 0x20a, 0x20b, 0x29a, 0x29b,
    ];

    #[test]
    fn firmware_read_fields_match_reference() {
        let part = &crate::parts::sh68f90a::PART;
        for (power, t, stored) in [
            (Power::V3_3, 3u8, BLOCK_3V3_T3),
            (Power::V5_0, 4u8, BLOCK_5V_T4),
        ] {
            let settings = Settings {
                power,
                power_on_time: t,
                ..Settings::default()
            };
            let built = build_block(
                part,
                "SH68F90A",
                &settings,
                &Project::default(),
                &[0; 8],
                chrono::NaiveDateTime::default(),
            );
            for &i in FIRMWARE_READ {
                assert_eq!(built[i], stored[i], "offset {i:#05x}");
            }
            for i in 0xa0..0xbb {
                assert_eq!(built[i], stored[i], "offset {i:#05x}");
            }
        }
    }

    /// Everything but the fields that depend on what was loaded and selected for a run (image,
    /// option edits, auto steps, build time) and on the tool version that produced the reference
    /// (no JTAG ID, a different version at `0x3f6`, and no CRC-32).
    #[test]
    fn matches_reference_outside_project_fields() {
        let part = &crate::parts::sh68f90a::PART;
        let differs = |i: usize| {
            i == 0x02
                || i == 0x11
                || (0x24..0x26).contains(&i)
                || (0x30..0x33).contains(&i)
                || (0x44..0x4c).contains(&i)
                || (0x58..0x5c).contains(&i)
                || (0x6c..0x70).contains(&i)
                || (0xf0..0xf8).contains(&i)
                || (0x3f0..0x3f8).contains(&i)
        };
        let settings = Settings {
            power: Power::V3_3,
            power_on_time: 3,
            ..Settings::default()
        };
        let built = build_block(
            part,
            "SH68F90A",
            &settings,
            &Project::default(),
            &[0; 8],
            chrono::NaiveDateTime::default(),
        );
        let diffs: Vec<String> = (0..BLOCK_LEN)
            .filter(|&i| !differs(i) && built[i] != BLOCK_3V3_T3[i])
            .map(|i| {
                format!(
                    "{i:#05x}: built {:02x} reference {:02x}",
                    built[i], BLOCK_3V3_T3[i]
                )
            })
            .collect();
        assert!(diffs.is_empty(), "{}", diffs.join("\n"));
    }

    #[test]
    fn crcs_match_their_catalogue_checks() {
        assert_eq!(crc16(b"123456789"), 0x29b1);
        assert_eq!(crc32(b"123456789"), 0x0376_e6e7);
    }

    #[test]
    fn checksum_balances() {
        let b = build_block(
            &crate::parts::sh68f90a::PART,
            "SH68F90A",
            &Settings::default(),
            &Project::default(),
            &[0; 8],
            chrono::NaiveDateTime::default(),
        );
        let sum: u32 = (0..BLOCK_COMPARED)
            .filter(|&i| {
                !((0xc2..=0xc5).contains(&i)
                    || (0xd2..=0xd5).contains(&i)
                    || (0x246..=0x24d).contains(&i))
            })
            .map(|i| u32::from(b[i]))
            .sum();
        assert_eq!(sum as u8, 0);
    }

    #[test]
    fn boot_rom_sets_isp_block_fields() {
        use field::*;
        let part = &crate::parts::sh79f6488::PART;
        let get32 =
            |b: &[u8; BLOCK_LEN], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let off = build_block(
            part,
            "SH79F6488",
            &Settings::default(),
            &Project::default(),
            &[0; 8],
            chrono::NaiveDateTime::default(),
        );
        assert_eq!(off[BOOT_AREA], 0);
        assert_eq!(get32(&off, BOOT_BLK), 0);

        let settings = Settings {
            boot_rom: true,
            ..Settings::default()
        };
        let on = build_block(
            part,
            "SH79F6488",
            &settings,
            &Project::default(),
            &[0; 8],
            chrono::NaiveDateTime::default(),
        );
        assert_eq!(on[BOOT_AREA], 1);
        let isp = part.isp_size;
        assert_eq!(get32(&on, ISP_SIZE), isp);
        assert_eq!(get32(&on, CODE_LEN), get32(&on, BOOT_BLK) + isp);
        assert_eq!(get32(&on, CRC32_LEN), get32(&on, CODE_LEN) - isp);
    }

    #[test]
    fn family2_erase_type_widens_and_guards() {
        let want = [0x0f, 0x00, 0x00, 0x88];
        // Same partition: base type (2 with boot).
        assert_eq!(
            family2_erase_type(&[0x0f, 0x00, 0x00, 0x88], &want, false),
            1
        );
        assert_eq!(
            family2_erase_type(&[0x0f, 0x00, 0x00, 0x88], &want, true),
            2
        );
        // Low-nibble (E2) difference widens to 4, or 5 with boot.
        assert_eq!(
            family2_erase_type(&[0x0f, 0x00, 0x00, 0x80], &want, false),
            4
        );
        assert_eq!(
            family2_erase_type(&[0x0f, 0x00, 0x00, 0x80], &want, true),
            5
        );
        // High-nibble (ISP) difference widens to 5.
        assert_eq!(
            family2_erase_type(&[0x0f, 0x00, 0x00, 0x08], &want, false),
            5
        );
        // All 0xFF is a read-protected part: do not widen, use the base type.
        assert_eq!(family2_erase_type(&[0xff; 4], &want, false), 1);
        assert_eq!(family2_erase_type(&[0xff; 4], &want, true), 2);
    }
}
