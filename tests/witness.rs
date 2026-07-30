use std::{
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use telosieve::{
    attestation_witness::{
        RevokedSigner, WitnessTrust, sign_revocations, verify_witnessed_attestation,
        witness_attestation,
    },
    certificate_attestation::{
        AttestationKey, AttestationTrust, attest_certificate, verify_attestation,
    },
};

fn run_python(
    directory: &std::path::Path,
    certificate: &[u8],
    attestation: &[u8],
    attestation_trust: &AttestationTrust,
    timestamps: &[u8],
    revocations: &[u8],
    witness_trust: &WitnessTrust,
) -> (bool, bool) {
    let paths = [
        ("attestation.json", attestation),
        (
            "attestation-trust.json",
            &serde_json::to_vec(attestation_trust).unwrap(),
        ),
        ("timestamps.json", timestamps),
        ("revocations.json", revocations),
        (
            "witness-trust.json",
            &serde_json::to_vec(witness_trust).unwrap(),
        ),
    ];
    for (name, bytes) in paths {
        fs::write(directory.join(name), bytes).unwrap();
    }
    let mut child = Command::new("python3")
        .arg("scripts/certificate-reader.py")
        .args([
            "--attestation",
            directory.join("attestation.json").to_str().unwrap(),
        ])
        .args([
            "--trust",
            directory.join("attestation-trust.json").to_str().unwrap(),
        ])
        .args([
            "--timestamps",
            directory.join("timestamps.json").to_str().unwrap(),
        ])
        .args([
            "--revocations",
            directory.join("revocations.json").to_str().unwrap(),
        ])
        .args([
            "--witness-trust",
            directory.join("witness-trust.json").to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = certificate.to_vec();
    let mut stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || stdin.write_all(&payload));
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    writer.join().unwrap().unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    (status.success(), timed_out)
}

#[test]
#[allow(clippy::too_many_lines)]
fn rust_and_python_enforce_timestamp_tip_and_revocation_boundary() {
    let directory = std::env::temp_dir().join(format!("telosieve-witness-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let certificate = fs::read("results/kubernetes-shadow-certificate.json").unwrap();
    let signer = SigningKey::from_bytes(&[61; 32]);
    let timestamp_key = SigningKey::from_bytes(&[62; 32]);
    let revocation_key = SigningKey::from_bytes(&[63; 32]);
    let attestation = attest_certificate(
        &certificate,
        "telosieve/research",
        "evidence-lab",
        "2026-a",
        100,
        900,
        &signer,
    )
    .unwrap();
    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
    let attestation_trust = AttestationTrust {
        context: "telosieve/research".into(),
        evaluation_time: 700,
        keys: vec![AttestationKey {
            signer: "evidence-lab".into(),
            key_id: "2026-a".into(),
            public_key: hex::encode(signer.verifying_key().to_bytes()),
            not_before: 50,
            not_after: 800,
        }],
    };
    let verified =
        verify_attestation(&certificate, &attestation_bytes, &attestation_trust).unwrap();
    let timestamp = witness_attestation(
        &attestation_bytes,
        "telosieve/research",
        1,
        None,
        200,
        "timestamp-lab",
        "clock-a",
        &timestamp_key,
    )
    .unwrap();
    let tip = timestamp.digest();
    let timestamps = serde_json::to_vec(&vec![timestamp]).unwrap();
    let historical = serde_json::to_vec(
        &sign_revocations(
            "telosieve/research",
            1,
            600,
            800,
            vec![RevokedSigner {
                signer: "evidence-lab".into(),
                key_id: "2026-a".into(),
                revoked_at: 300,
            }],
            "revocation-lab",
            "root-a",
            &revocation_key,
        )
        .unwrap(),
    )
    .unwrap();
    let trust = WitnessTrust {
        context: "telosieve/research".into(),
        evaluation_time: 700,
        timestamp_authority: "timestamp-lab".into(),
        timestamp_key_id: "clock-a".into(),
        timestamp_public_key: hex::encode(timestamp_key.verifying_key().to_bytes()),
        trusted_tip_sequence: 1,
        trusted_tip_digest: tip,
        revocation_authority: "revocation-lab".into(),
        revocation_key_id: "root-a".into(),
        revocation_public_key: hex::encode(revocation_key.verifying_key().to_bytes()),
        trusted_revocation_sequence: 1,
        trusted_revocation_digest: hex::encode(Sha256::digest(&historical)),
    };
    verify_witnessed_attestation(
        &verified,
        &attestation_bytes,
        &timestamps,
        &historical,
        &trust,
    )
    .unwrap();
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &historical,
            &trust,
        ),
        (true, false)
    );
    let pretty_historical = serde_json::to_vec_pretty(
        &serde_json::from_slice::<serde_json::Value>(&historical).unwrap(),
    )
    .unwrap();
    let mut pretty_trust = trust.clone();
    pretty_trust.trusted_revocation_digest = hex::encode(Sha256::digest(&pretty_historical));
    verify_witnessed_attestation(
        &verified,
        &attestation_bytes,
        &timestamps,
        &pretty_historical,
        &pretty_trust,
    )
    .unwrap();
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &pretty_historical,
            &pretty_trust,
        ),
        (true, false)
    );

    let revoked = serde_json::to_vec(
        &sign_revocations(
            "telosieve/research",
            1,
            600,
            800,
            vec![RevokedSigner {
                signer: "evidence-lab".into(),
                key_id: "2026-a".into(),
                revoked_at: 200,
            }],
            "revocation-lab",
            "root-a",
            &revocation_key,
        )
        .unwrap(),
    )
    .unwrap();
    let mut revoked_trust = trust.clone();
    revoked_trust.trusted_revocation_digest = hex::encode(Sha256::digest(&revoked));
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &timestamps,
            &revoked,
            &revoked_trust,
        )
        .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &revoked,
            &revoked_trust,
        ),
        (false, false)
    );
    let mut rollback = trust.clone();
    rollback.trusted_tip_sequence = 2;
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &timestamps,
            &historical,
            &rollback,
        )
        .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &historical,
            &rollback,
        ),
        (false, false)
    );
    assert!(
        verify_witnessed_attestation(&verified, &attestation_bytes, &timestamps, &revoked, &trust,)
            .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &revoked,
            &trust,
        ),
        (false, false)
    );
    let mut stale = trust.clone();
    stale.evaluation_time = 800;
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &timestamps,
            &historical,
            &stale,
        )
        .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &timestamps,
            &historical,
            &stale,
        ),
        (false, false)
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&timestamps).unwrap();
    tampered[0]["signature"] = serde_json::Value::String("00".repeat(64));
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &tampered,
            &historical,
            &trust,
        )
        .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            &tampered,
            &historical,
            &trust,
        ),
        (false, false)
    );
    assert!(
        verify_witnessed_attestation(&verified, &attestation_bytes, b"[]", &historical, &trust,)
            .is_err()
    );
    assert_eq!(
        run_python(
            &directory,
            &certificate,
            &attestation_bytes,
            &attestation_trust,
            b"[]",
            &historical,
            &trust,
        ),
        (false, false)
    );
    let mut substituted_attestation = attestation.clone();
    substituted_attestation.signer = "other-lab".into();
    let substituted_bytes = serde_json::to_vec(&substituted_attestation).unwrap();
    let substituted_timestamp = witness_attestation(
        &substituted_bytes,
        "telosieve/research",
        1,
        None,
        200,
        "timestamp-lab",
        "clock-a",
        &timestamp_key,
    )
    .unwrap();
    let mut substituted_trust = trust.clone();
    substituted_trust.trusted_tip_digest = substituted_timestamp.digest();
    let substituted_timestamps = serde_json::to_vec(&vec![substituted_timestamp]).unwrap();
    assert!(
        verify_witnessed_attestation(
            &verified,
            &substituted_bytes,
            &substituted_timestamps,
            &historical,
            &substituted_trust,
        )
        .is_err()
    );
    fs::remove_dir_all(directory).unwrap();
}
