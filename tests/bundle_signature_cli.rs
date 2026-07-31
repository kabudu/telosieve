use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telosieve"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn real_cli_signs_exact_bundle_and_refuses_tamper_time_key_and_unsafe_key() {
    let root = Path::new("target")
        .join("bundle-signature-cli")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let bundle = root.join("bundle.zip");
    let key = root.join("release-key.hex");
    let signature = root.join("bundle.signature.json");
    let trust = root.join("trust.json");
    fs::write(&bundle, b"exact deterministic private bundle").unwrap();
    fs::write(&key, hex::encode([91; 32])).unwrap();
    let mut permissions = fs::metadata(&key).unwrap().permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&key, permissions).unwrap();
    let key_path = fs::canonicalize(&key).unwrap();
    let bundle_path = fs::canonicalize(&bundle).unwrap();
    let public = run(&["bundle-public-key", key_path.to_str().unwrap()]);
    assert!(public.status.success());
    let public = String::from_utf8(public.stdout).unwrap().trim().to_string();
    let output = run(&[
        "bundle-sign",
        bundle_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        "telosieve/private-evaluation",
        "release-lab",
        "key-a",
        "100",
        "200",
        fs::canonicalize(&root)
            .unwrap()
            .join("bundle.signature.json")
            .to_str()
            .unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&fs::read(&signature).unwrap()).unwrap();
    assert!(
        !serde_json::to_string(&envelope)
            .unwrap()
            .contains(&hex::encode([91; 32]))
    );
    fs::write(&trust, serde_json::to_vec(&json!({"context":"telosieve/private-evaluation","evaluation_time":150,"keys":[{"signer":"release-lab","key_id":"key-a","public_key":public,"not_before":50,"not_after":250}]})).unwrap()).unwrap();
    let trust_path = fs::canonicalize(&trust).unwrap();
    let signature_path = fs::canonicalize(&signature).unwrap();
    assert!(
        run(&[
            "bundle-verify",
            bundle_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            trust_path.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::write(&bundle, b"tampered bundle").unwrap();
    assert!(
        !run(&[
            "bundle-verify",
            bundle_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            trust_path.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::write(&bundle, b"exact deterministic private bundle").unwrap();
    let mut expired: Value = serde_json::from_slice(&fs::read(&trust).unwrap()).unwrap();
    expired["evaluation_time"] = 201.into();
    fs::write(&trust, serde_json::to_vec(&expired).unwrap()).unwrap();
    assert!(
        !run(&[
            "bundle-verify",
            bundle_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            trust_path.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !run(&["bundle-public-key", key_path.to_str().unwrap()])
            .status
            .success()
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.join("release-key-alias.hex");
    fs::hard_link(&key, &alias).unwrap();
    assert!(
        !run(&["bundle-public-key", key_path.to_str().unwrap()])
            .status
            .success()
    );
    let _ = fs::remove_dir_all(root);
}
