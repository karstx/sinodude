// Auto-generated from GPT file for XA2000

use super::{AddressField, Options, Part, SecurityRecordFormat, Voltage};
use hex_literal::hex;
use indexmap::IndexMap;

pub const PART: Part = Part {
    part_number: hex!("5841200000"),
    chip_type: 0x02,
    custom_block: 0x02,
    product_block: 0x01,
    flash_size: 16384,
    eeprom_size: 0,
    default_code_options: &hex!("00000000"),
    code_option_mask: &hex!("01000000"),
    jtag_id: 0xf830,
    sector_size: 1024,
    option_byte_count: 4,
    security_level: 0,
    bank_type: 0,
    reset_pin: 0,
    erase_delay: 0,
    frequency_division: 0,
    writer_capacity: 0x4d7ef,
    iap: 0,
    isp_size: 0,
    chip_version: 0,
    part_num_address: 0x0,
    customer_id: AddressField { address: 0x0800 },
    operation_number: AddressField { address: 0x0804 },
    customer_option: AddressField { address: 0x0806 },
    security: AddressField { address: 0x080a },
    serial_number: AddressField { address: 0x083c },
    compatible_voltages: &[Voltage::V5_0],
    options,
    security_record_format: SecurityRecordFormat::Record19,
};

/// Get all code options metadata
pub fn options() -> Options {
    IndexMap::new()
}
