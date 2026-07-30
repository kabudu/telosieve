use std::{
    fs,
    io::{Read, Write},
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use telosieve::{
    certificate_attestation::{
        AttestationKey, AttestationTrust, CertificateAttestation, attest_certificate,
        verify_attestation,
    },
    engine::run_scenario,
    protocol::Scenario,
};

const MAX_QUALIFICATION_CASES: usize = 12;
const MAX_QUALIFICATION_BYTES: usize = 2 * 1024 * 1024;

fn create_certificate(path: &str) -> Vec<u8> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    serde_json::to_vec(&run_scenario(&scenario).unwrap()).unwrap()
}

fn key_record(
    signer: &str,
    key_id: &str,
    key: &SigningKey,
    not_before: u64,
    not_after: u64,
) -> AttestationKey {
    AttestationKey {
        signer: signer.into(),
        key_id: key_id.into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        not_before,
        not_after,
    }
}

fn run_python(
    directory: &std::path::Path,
    label: &str,
    certificate: &[u8],
    attestation: &CertificateAttestation,
    trust: &AttestationTrust,
) -> (std::process::Output, bool) {
    let attestation_path = directory.join(format!("{label}-attestation.json"));
    let trust_path = directory.join(format!("{label}-trust.json"));
    fs::write(&attestation_path, serde_json::to_vec(attestation).unwrap()).unwrap();
    fs::write(&trust_path, serde_json::to_vec(trust).unwrap()).unwrap();
    let mut child = Command::new("python3")
        .arg("scripts/certificate-reader.py")
        .arg("--attestation")
        .arg(&attestation_path)
        .arg("--trust")
        .arg(&trust_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let payload = certificate.to_vec();
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
    let _ = writer.join().unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    (
        std::process::Output {
            status,
            stdout,
            stderr,
        },
        timed_out,
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn rust_and_python_verify_rotation_and_fail_closed_attestations() {
    let directory = std::env::temp_dir().join(format!("telosieve-attestation-{}", process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();

    let certificate = create_certificate("scenarios/benign.json");
    let other_certificate = create_certificate("scenarios/poisoned-goal.json");
    let old = SigningKey::from_bytes(&[41; 32]);
    let new = SigningKey::from_bytes(&[42; 32]);
    let keys = vec![
        key_record("evidence-lab", "2026-a", &old, 100, 300),
        key_record("evidence-lab", "2026-b", &new, 250, 900),
    ];
    let trust = AttestationTrust {
        context: "telosieve/research".into(),
        evaluation_time: 600,
        keys,
    };
    let old_attestation = attest_certificate(
        &certificate,
        "telosieve/research",
        "evidence-lab",
        "2026-a",
        200,
        700,
        &old,
    )
    .unwrap();
    let new_attestation = attest_certificate(
        &certificate,
        "telosieve/research",
        "evidence-lab",
        "2026-b",
        300,
        800,
        &new,
    )
    .unwrap();

    let mut case_bytes = certificate.len() + other_certificate.len();
    for (label, attestation) in [("old-key", &old_attestation), ("new-key", &new_attestation)] {
        let bytes = serde_json::to_vec(attestation).unwrap();
        verify_attestation(&certificate, &bytes, &trust).unwrap();
        let (output, timed_out) = run_python(&directory, label, &certificate, attestation, &trust);
        assert!(!timed_out);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["attestation"]["status"], "verified");
        assert_eq!(summary["attestation"]["key_id"], attestation.key_id);
        case_bytes += bytes.len();
    }

    let mut tampered = old_attestation.clone();
    let replacement = if tampered.signature.starts_with("00") {
        "01"
    } else {
        "00"
    };
    tampered.signature.replace_range(0..2, replacement);
    let mut wrong_context = trust.clone();
    wrong_context.context = "other/research".into();
    let mut expired = trust.clone();
    expired.evaluation_time = old_attestation.expires_at;
    let outside_key = attest_certificate(
        &certificate,
        "telosieve/research",
        "evidence-lab",
        "2026-a",
        400,
        700,
        &old,
    )
    .unwrap();

    let rejected = [
        ("tampered", certificate.as_slice(), tampered, trust.clone()),
        (
            "wrong-certificate",
            other_certificate.as_slice(),
            old_attestation.clone(),
            trust.clone(),
        ),
        (
            "cross-context",
            certificate.as_slice(),
            old_attestation.clone(),
            wrong_context,
        ),
        (
            "expired",
            certificate.as_slice(),
            old_attestation.clone(),
            expired,
        ),
        (
            "outside-key",
            certificate.as_slice(),
            outside_key,
            trust.clone(),
        ),
    ];
    assert!(2 + rejected.len() <= MAX_QUALIFICATION_CASES);
    for (label, input, attestation, candidate_trust) in rejected {
        let bytes = serde_json::to_vec(&attestation).unwrap();
        assert!(verify_attestation(input, &bytes, &candidate_trust).is_err());
        let (output, timed_out) =
            run_python(&directory, label, input, &attestation, &candidate_trust);
        assert!(!timed_out);
        assert!(!output.status.success());
        case_bytes += bytes.len();
    }
    assert!(case_bytes <= MAX_QUALIFICATION_BYTES);
    fs::remove_dir_all(directory).unwrap();
}
