use serde_json::{json, Value};


pub fn format_block_tag(block_number: u64) -> Value {
    json!(format!("0x{:x}", block_number))
}
