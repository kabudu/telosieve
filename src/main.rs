use ed25519_dalek::SigningKey;
use std::{env, fmt::Display, fs, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if let Some(outcome) = product_command(&args) {
        return outcome;
    }
    match args.get(1).map(String::as_str) {
        Some("evaluate") if args.len() == 3 => evaluate(Path::new(&args[2])),
        Some("anchor-init") if args.len() == 4 => {
            match telosieve::engine::initialize_anchor_file(
                Path::new(&args[2]),
                Path::new(&args[3]),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-init") if args.len() == 4 => {
            match telosieve::engine::initialize_actuator_file(
                Path::new(&args[2]),
                Path::new(&args[3]),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-show") if args.len() == 3 => {
            match telosieve::engine::read_actuator_snapshot_file(Path::new(&args[2])) {
                Ok(snapshot) => {
                    println!(
                        "{}",
                        serde_json::to_string(&snapshot).expect("actuator snapshot serializes")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            }
        }
        Some("local-backup") if args.len() == 4 => {
            match telosieve::engine::backup_actuator_file(Path::new(&args[2]), Path::new(&args[3]))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-restore") if args.len() == 4 => {
            match telosieve::engine::restore_actuator_file(Path::new(&args[2]), Path::new(&args[3]))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("local-recover") if args.len() == 3 => {
            match telosieve::engine::recover_actuator_file(Path::new(&args[2])) {
                Ok(outcome) => {
                    println!(
                        "{}",
                        serde_json::to_string(&outcome).expect("recovery outcome serializes")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            }
        }
        Some("local-upgrade") if args.len() == 3 => {
            match telosieve::engine::upgrade_actuator_file(Path::new(&args[2])) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some("run") if args.len() == 5 => emit(telosieve::engine::run_scenario_file(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        )),
        Some("shadow-kubernetes") if args.len() == 6 => {
            emit(telosieve::engine::run_kubernetes_shadow_file(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ))
        }
        Some("run-anchored") if args.len() == 6 => {
            emit(telosieve::engine::run_scenario_file_anchored(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ))
        }
        Some("apply-local") if args.len() == 6 => {
            emit(telosieve::engine::run_scenario_file_actuated(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ))
        }
        _ => usage(),
    }
}

fn product_command(args: &[String]) -> Option<ExitCode> {
    match args.get(1).map(String::as_str) {
        Some("--version") if args.len() == 2 => {
            println!("telosieve {}", env!("CARGO_PKG_VERSION"));
            Some(ExitCode::SUCCESS)
        }
        Some("bundle-sign") if args.len() == 10 => Some(bundle_sign(args)),
        Some("bundle-verify") if args.len() == 5 => Some(bundle_verify(args)),
        Some("bundle-public-key") if args.len() == 3 => Some(bundle_public_key(&args[2])),
        _ => None,
    }
}

fn evaluate(config_path: &Path) -> ExitCode {
    match telosieve::evaluation::run_config_file(config_path) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string(&report).expect("evaluation report serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

fn bundle_sign(args: &[String]) -> ExitCode {
    let result = (|| -> Result<(), String> {
        let bundle_path = Path::new(&args[2]);
        let key_path = Path::new(&args[3]);
        let output = Path::new(&args[9]);
        if !bundle_path.is_absolute()
            || !key_path.is_absolute()
            || !output.is_absolute()
            || output.exists()
            || output == bundle_path
            || output == key_path
        {
            return Err("bundle signature output collision".into());
        }
        validate_private_key_path(key_path)?;
        let bundle = read_bounded(bundle_path, telosieve::bundle_signature::MAX_BUNDLE_BYTES)?;
        let key_hex = fs::read_to_string(key_path).map_err(|error| error.to_string())?;
        if key_hex.len() > 128 {
            return Err("bundle signing key exceeds bound".into());
        }
        let key: [u8; 32] = hex::decode(key_hex.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bundle signing key must be 32-byte hexadecimal")?;
        let issued = args[7].parse().map_err(|_| "issued_at is invalid")?;
        let expires = args[8].parse().map_err(|_| "expires_at is invalid")?;
        let signature = telosieve::bundle_signature::sign_bundle(
            &bundle,
            &args[4],
            &args[5],
            &args[6],
            issued,
            expires,
            &SigningKey::from_bytes(&key),
        )
        .map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&signature).map_err(|error| error.to_string())?;
        write_private_new(output, &bytes)?;
        println!(
            "{}",
            serde_json::to_string(&signature).expect("bundle signature serializes")
        );
        Ok(())
    })();
    result.map_or_else(|error| fail(&error), |()| ExitCode::SUCCESS)
}

fn bundle_public_key(value: &str) -> ExitCode {
    let result = (|| -> Result<String, String> {
        let path = Path::new(value);
        validate_private_key_path(path)?;
        let encoded = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let key: [u8; 32] = hex::decode(encoded.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("bundle signing key must be 32-byte hexadecimal")?;
        Ok(hex::encode(
            SigningKey::from_bytes(&key).verifying_key().to_bytes(),
        ))
    })();
    match result {
        Ok(public) => {
            println!("{public}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

fn validate_private_key_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.is_symlink() || !path.is_file() {
        return Err("bundle signing key must be an absolute regular file".into());
    }
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() == 0 || metadata.len() > 128 {
        return Err("bundle signing key must contain at most 128 bytes".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("bundle signing key must be owner-only".into());
        }
        if metadata.nlink() != 1 {
            return Err("bundle signing key must not have hard-link aliases".into());
        }
    }
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().ok_or("signature output has no parent")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("invalid signature output")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::hard_link(&temporary, path).map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn bundle_verify(args: &[String]) -> ExitCode {
    let result = (|| -> Result<telosieve::bundle_signature::BundleSignature, String> {
        let bundle = read_bounded(
            Path::new(&args[2]),
            telosieve::bundle_signature::MAX_BUNDLE_BYTES,
        )?;
        let signature = read_bounded(
            Path::new(&args[3]),
            telosieve::bundle_signature::MAX_SIGNATURE_BYTES,
        )?;
        let trust_bytes = read_bounded(
            Path::new(&args[4]),
            telosieve::bundle_signature::MAX_SIGNATURE_BYTES,
        )?;
        let trust = serde_json::from_slice(&trust_bytes).map_err(|error| error.to_string())?;
        telosieve::bundle_signature::verify_bundle(&bundle, &signature, &trust)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(signature) => {
            println!(
                "{}",
                serde_json::to_string(&signature).expect("bundle signature serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    if !path.is_absolute() || path.is_symlink() || !path.is_file() {
        return Err("bundle input must be an absolute regular file".into());
    }
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > u64::try_from(maximum).map_err(|_| "input bound is unsupported")? {
        return Err("bundle input exceeds bound".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  telosieve anchor-init <scenario.json> <anchor.json>\n  \
         telosieve evaluate <evaluation-config.json>\n  \
         telosieve bundle-sign <bundle.zip> <private-key.hex> <context> <signer> <key-id> <issued-at> <expires-at> <signature.json>\n  \
         telosieve bundle-public-key <private-key.hex>\n  \
         telosieve bundle-verify <bundle.zip> <signature.json> <trust.json>\n  \
         telosieve local-init <scenario.json> <actuator.json>\n  \
         telosieve local-show <actuator.json>\n  \
         telosieve local-backup <actuator.json> <backup.json>\n  \
         telosieve local-restore <actuator.json> <backup.json>\n  \
         telosieve local-recover <actuator.json>\n  \
         telosieve local-upgrade <actuator.json>\n  \
         telosieve run <scenario.json> <certificate.json> <ledger.jsonl>\n  \
         telosieve shadow-kubernetes <scenario.json> <snapshot.json> \
         <certificate.json> <ledger.jsonl>\n  \
         telosieve run-anchored <scenario.json> <certificate.json> \
         <ledger.jsonl> <anchor.json>\n  \
         telosieve apply-local <scenario.json> <certificate.json> \
         <ledger.jsonl> <actuator.json>"
    );
    ExitCode::from(2)
}

fn emit(
    result: Result<telosieve::certificate::Certificate, telosieve::engine::RunError>,
) -> ExitCode {
    match result {
        Ok(certificate) => {
            println!(
                "{}",
                serde_json::to_string(&certificate).expect("certificate serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

fn fail(error: &impl Display) -> ExitCode {
    eprintln!("telosieve: {error}");
    ExitCode::FAILURE
}
