use crate::WirelessDevice;
use std::process::Command;
pub fn scan(interface: &str) -> Vec<WirelessDevice> {
    let mut devices = Vec::new();
    if cfg!(target_os = "macos") {
        if let Ok(out) = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport").args(["-s"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    devices.push(WirelessDevice { mac: parts[1].into(), name: parts[0].into(), device_type: "Access Point".into(), protocol: "Wi-Fi".into(), signal_dbm: parts[2].parse().unwrap_or(-99), channel: parts[3].parse().ok(), encryption: Some(parts[parts.len()-1].into()) });
                }
            }
        }
    }
    let _ = interface;
    devices
}
pub fn list_interfaces() { eprintln!("  Wi-Fi: en0 (built-in)"); }
