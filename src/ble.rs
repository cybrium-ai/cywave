use crate::WirelessDevice;
pub async fn scan(_duration: u64) -> Vec<WirelessDevice> {
    eprintln!("  BLE: requires btleplug (placeholder)");
    Vec::new()
}
