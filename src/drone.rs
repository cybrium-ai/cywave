use crate::WirelessDevice;
use remoteid::{ble, wifi, Frame, Message};

/// Decode a captured BLE advertisement as an ASTM F3411 / EN 4709 Remote ID
/// broadcast. Returns a drone `WirelessDevice` when the advertising data
/// carries the Remote ID service UUID (0xFFFA), otherwise `None`.
pub fn from_ble_advertisement(mac: &str, signal_dbm: i32, adv: &[u8]) -> Option<WirelessDevice> {
    let rid = ble::find_in_advertising_data(adv)?;
    let frame = rid.frame().ok()?;
    Some(device_from_frame(mac, "BLE Remote ID", signal_dbm, &frame))
}

/// Decode a captured Wi-Fi Beacon or NAN action frame carrying the Remote ID
/// vendor element. Returns a drone `WirelessDevice`, otherwise `None`.
pub fn from_wifi_frame(mac: &str, signal_dbm: i32, frame_bytes: &[u8]) -> Option<WirelessDevice> {
    let rid = wifi::parse_frame(frame_bytes).ok()?;
    let frame = rid.frame().ok()?;
    Some(device_from_frame(
        mac,
        "Wi-Fi Remote ID",
        signal_dbm,
        &frame,
    ))
}

fn device_from_frame(mac: &str, protocol: &str, signal_dbm: i32, frame: &Frame) -> WirelessDevice {
    let mut id = None;
    frame.for_each_message(|m| {
        if let Message::BasicId(b) = m {
            if let Some(s) = b.uas_id_str() {
                if !s.is_empty() {
                    id = Some(s.to_string());
                }
            }
        }
    });
    WirelessDevice {
        mac: mac.to_string(),
        name: id.unwrap_or_else(|| "Remote ID drone".to_string()),
        device_type: "Drone (Remote ID)".to_string(),
        protocol: protocol.to_string(),
        signal_dbm,
        channel: None,
        encryption: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoteid::{BasicId, IdType, UaType};

    #[test]
    fn decodes_remote_id_drone_from_ble_advertisement() {
        // A real ASTM F3411 Basic ID broadcast from a drone with serial 1596F3411SIM01.
        let basic = BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "1596F3411SIM01",
        )
        .unwrap();
        let msg = basic.encode().unwrap();
        let mut adv = [0u8; 31];
        let len = ble::write_advertising_data(0, &msg, &mut adv).unwrap();

        // Before: cywave had no Remote ID decode and reported zero drones.
        let device = from_ble_advertisement("aa:bb:cc:dd:ee:ff", -42, &adv[..len])
            .expect("Remote ID advertisement must be detected as a drone");
        assert_eq!(device.device_type, "Drone (Remote ID)");
        assert_eq!(device.name, "1596F3411SIM01");

        // A plain BLE advertisement with no Remote ID element is not a drone.
        let plain = [0x02u8, 0x01, 0x06];
        assert!(from_ble_advertisement("11:22:33:44:55:66", -60, &plain).is_none());
    }
}
