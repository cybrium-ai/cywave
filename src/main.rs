mod wifi; mod ble; mod drone; mod hardware_rot; mod output;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "cywave", version, about = "Wireless RF sensor — Cybrium AI")]
struct Cli { #[command(subcommand)] command: Commands }
#[derive(Subcommand)]
enum Commands {
    Scan { #[arg(short, long, default_value = "en0")] interface: String, #[arg(short, long, default_value = "30")] duration: u64, #[arg(short, long, default_value = "wifi,ble")] protocols: String, #[arg(short = 'f', long, default_value = "text")] format: String },
    Interfaces,
    Version,
    /// Decode a captured Remote ID advertisement (ASTM F3411 / EN 4709) and
    /// report any detected drone. Pass the raw bytes as hex, e.g. from a BLE
    /// 0xFFFA service-data advertisement.
    Drone { #[arg(short = 'x', long)] hex: String, #[arg(short, long, default_value = "ble")] link: String, #[arg(short = 'f', long, default_value = "text")] format: String },
    /// Report this host's hardware Root of Trust (TPM / Secure Enclave).
    /// Detection only — feeds sensor-attribution and tamper-detection
    /// flows. JSON output: {kind, vendor, present}.
    Rot,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessDevice { pub mac: String, pub name: String, pub device_type: String, pub protocol: String, pub signal_dbm: i32, pub channel: Option<u32>, pub encryption: Option<String> }

fn print_banner() {
    eprintln!("\x1b[35m\n   ___  _   _ __      __  _  __   __ ___ \n  / __|| | | |\\ \\    / / /_\\ \\ \\ / /| __|\n | (__ | |_| | \\ \\/\\/ / / _ \\ \\ V / | _| \n  \\___| \\__, |  \\_/\\_/ /_/ \\_\\ \\_/  |___|\n        |___/\n\x1b[0m");
    eprintln!("  \x1b[35m\x1b[1mcywave\x1b[0m v{} — \x1b[2mCybrium AI Wireless Sensor\x1b[0m\n", env!("CARGO_PKG_VERSION"));
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { interface, duration, protocols, format } => {
            print_banner();
            let mut devices = Vec::new();
            if protocols.contains("wifi") { devices.extend(wifi::scan(&interface)); }
            if protocols.contains("ble") { devices.extend(ble::scan(duration).await); }
            output::print_devices(&devices, &format);
        }
        Commands::Interfaces => { print_banner(); wifi::list_interfaces(); }
        Commands::Drone { hex, link, format } => {
            print_banner();
            let bytes: Vec<u8> = match (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or(""), 16)).collect::<Result<_, _>>() {
                Ok(b) => b,
                Err(_) => { eprintln!("  invalid hex"); std::process::exit(1); }
            };
            let device = if link == "wifi" { drone::from_wifi_frame("unknown", -50, &bytes) } else { drone::from_ble_advertisement("unknown", -50, &bytes) };
            output::print_devices(&device.into_iter().collect::<Vec<_>>(), &format);
        }
        Commands::Version => println!("cywave {} — Cybrium AI Wireless Sensor", env!("CARGO_PKG_VERSION")),
        Commands::Rot => {
            let r = hardware_rot::detect();
            match serde_json::to_string_pretty(&r) {
                Ok(j)  => println!("{j}"),
                Err(e) => eprintln!("error serialising root-of-trust: {e}"),
            }
        }
    }
}
