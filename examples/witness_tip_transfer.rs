use std::path::Path;

use telosieve::witness_tip_store::{TrustedTips, WitnessTipStore};

fn expected() -> TrustedTips {
    TrustedTips {
        schema_version: "telosieve.witness-tip-state/v1".into(),
        generation: 1,
        timestamp_sequence: 1,
        timestamp_digest: "a".repeat(64),
        revocation_sequence: 1,
        revocation_digest: "b".repeat(64),
    }
}

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    let [_, operation, path] = arguments.as_slice() else {
        eprintln!("usage: witness_tip_transfer create|verify <tips.json>");
        std::process::exit(2);
    };
    let store = WitnessTipStore::new(Path::new(path));
    let result = match operation.as_str() {
        "create" => store.initialize(expected()),
        "verify" => store.read().and_then(|state| {
            if state == expected() {
                Ok(())
            } else {
                Err(telosieve::witness_tip_store::TipStoreError::InvalidState)
            }
        }),
        _ => {
            eprintln!("usage: witness_tip_transfer create|verify <tips.json>");
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("witness-tip-transfer: {error}");
        std::process::exit(1);
    }
}
