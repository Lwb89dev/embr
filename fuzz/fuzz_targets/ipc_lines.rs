//! Arbitrary bytes through the framing codec and every strictly-typed wire/control message.
#![no_main]
use embr_ipc::codec::read_line;
use embr_ipc::control::{ControlEvent, DecideParams, DecisionWire, Settings};
use embr_ipc::{ClientHello, DecryptParams, EncryptParams, Request, SignEventParams, parse_params};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Framing with a small limit so the "too long" paths are reached often.
    let mut reader = std::io::BufReader::with_capacity(16, data);
    while let Ok(Some(line)) = read_line(&mut reader, 4096) {
        let _ = serde_json::from_str::<Request>(&line);
        let _ = serde_json::from_str::<ClientHello>(&line);
        let _ = serde_json::from_str::<DecisionWire>(&line);
        let _ = serde_json::from_str::<DecideParams>(&line);
        let _ = serde_json::from_str::<ControlEvent>(&line);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            let _ = parse_params::<EncryptParams>(v.clone());
            let _ = parse_params::<DecryptParams>(v.clone());
            let _ = parse_params::<SignEventParams>(v.clone());
            if let Ok(s) = parse_params::<Settings>(v) {
                let _ = s.validate();
            }
        }
    }
});
