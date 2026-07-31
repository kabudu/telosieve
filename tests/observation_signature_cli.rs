use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use telosieve::observation_quorum::{
    ObservationAttestation, ObservationKey, ObservationQuorum, ObservationTrust,
    QUORUM_SCHEMA_VERSION, TRUST_SCHEMA_VERSION, verify_observation_quorum,
};

struct Directory(PathBuf);

impl Directory {
    fn create() -> Self {
        let path = Path::new("target")
            .join("observation-signature-cli-tests")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_key(path: &Path, seed: [u8; 32]) {
    fs::write(path, hex::encode(seed)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn sign(
    input: &Path,
    key: &Path,
    producer: &str,
    key_id: &str,
    domain: &str,
    output: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telosieve"))
        .args([
            "observation-sign",
            input.to_str().unwrap(),
            key.to_str().unwrap(),
            "kv/research",
            "kubernetes-live",
            producer,
            key_id,
            domain,
            "1788000000",
            "1788000300",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn observation_cli_signs_exact_input_and_refuses_unsafe_files() {
    let directory = Directory::create();
    let input = fs::canonicalize("snapshots/kubernetes-shadow-benign.json").unwrap();
    let specifications = [
        ("producer-a", "key-a", "domain-a", [3_u8; 32]),
        ("producer-b", "key-b", "domain-b", [4_u8; 32]),
    ];
    let mut attestations = Vec::new();
    let mut keys = Vec::new();
    for (index, (producer, key_id, domain, seed)) in specifications.iter().enumerate() {
        let key_path = directory.0.join(format!("key-{index}.hex"));
        let output_path = directory.0.join(format!("attestation-{index}.json"));
        write_key(&key_path, *seed);
        let public = Command::new(env!("CARGO_BIN_EXE_telosieve"))
            .args(["observation-public-key", key_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(public.status.success());
        assert_eq!(
            String::from_utf8(public.stdout).unwrap().trim(),
            hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
        );
        let result = sign(&input, &key_path, producer, key_id, domain, &output_path);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            result.stdout.strip_suffix(b"\n").unwrap(),
            fs::read(&output_path).unwrap()
        );
        attestations.push(
            serde_json::from_slice::<ObservationAttestation>(&fs::read(output_path).unwrap())
                .unwrap(),
        );
        keys.push(ObservationKey {
            producer: (*producer).into(),
            key_id: (*key_id).into(),
            fault_domain: (*domain).into(),
            public_key: hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes()),
            not_before: 1_788_000_000,
            not_after: 1_800_000_000,
        });
    }
    let input_bytes = fs::read(&input).unwrap();
    let trust = serde_json::to_vec(&ObservationTrust {
        schema_version: TRUST_SCHEMA_VERSION.into(),
        evaluation_time: 1_788_000_100,
        required_distinct_domains: 2,
        keys,
    })
    .unwrap();
    let quorum = serde_json::to_vec(&ObservationQuorum {
        schema_version: QUORUM_SCHEMA_VERSION.into(),
        subject: "kv/research".into(),
        mode: "kubernetes-live".into(),
        input_sha256: hex::encode(Sha256::digest(&input_bytes)),
        attestations,
    })
    .unwrap();
    assert!(
        verify_observation_quorum(
            &input_bytes,
            "kv/research",
            "kubernetes-live",
            &trust,
            &quorum,
        )
        .is_ok()
    );

    let unsafe_key = directory.0.join("unsafe-key.hex");
    write_key(&unsafe_key, [5_u8; 32]);
    fs::set_permissions(&unsafe_key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !sign(
            &input,
            &unsafe_key,
            "producer-c",
            "key-c",
            "domain-c",
            &directory.0.join("unsafe.json"),
        )
        .status
        .success()
    );
    assert!(!directory.0.join("unsafe.json").exists());

    let oversized = directory.0.join("oversized.bin");
    fs::write(
        &oversized,
        vec![0_u8; telosieve::observation_quorum::MAX_INPUT_BYTES + 1],
    )
    .unwrap();
    let safe_key = directory.0.join("safe-key.hex");
    write_key(&safe_key, [6_u8; 32]);
    assert!(
        !sign(
            &oversized,
            &safe_key,
            "producer-d",
            "key-d",
            "domain-d",
            &directory.0.join("oversized.json"),
        )
        .status
        .success()
    );
    assert!(
        !sign(&input, &safe_key, "p", "k", "d", &safe_key)
            .status
            .success()
    );
}
