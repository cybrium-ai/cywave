use crate::WirelessDevice;
use colored::Colorize;
pub fn print_devices(devices: &[WirelessDevice], format: &str) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(devices).unwrap()),
        _ => {
            eprintln!("  {} {} devices\n", "Found:".green().bold(), devices.len());
            for d in devices {
                let sig = if d.signal_dbm > -50 { d.signal_dbm.to_string().green() } else if d.signal_dbm > -70 { d.signal_dbm.to_string().yellow() } else { d.signal_dbm.to_string().red() };
                eprintln!("  {:<24} {} {:>5}dBm ch:{} {}", d.name, d.mac.dimmed(), sig, d.channel.map(|c| c.to_string()).unwrap_or("-".into()), d.encryption.as_deref().unwrap_or("").cyan());
            }
        }
    }
}
