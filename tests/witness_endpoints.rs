use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use serde_json::Value;
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

const TIMESTAMP_TOKEN: &str = "fixture-timestamp-token";
const REVOCATION_TOKEN: &str = "fixture-revocation-token";
const RESPONSE_BOUND: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_ENDPOINT_ATTEMPTS: usize = 3;
const MAX_HEADER_BYTES: usize = 4096;

struct Endpoint {
    child: Child,
    address: SocketAddr,
}

struct TestDirectory(std::path::PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!("telosieve-endpoints-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Endpoint {
    fn start(path: &std::path::Path, token: &str, mode: &str, delay_ms: u64) -> Self {
        let mut child = Command::new("python3")
            .arg("scripts/witness-endpoint.py")
            .args(["--artifact", path.to_str().unwrap()])
            .args(["--token", token])
            .args(["--mode", mode])
            .args(["--delay-ms", &delay_ms.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let line = receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| {
                let _ = child.kill();
                let _ = child.wait();
                panic!("witness endpoint readiness timed out");
            })
            .unwrap();
        let ready: Value = serde_json::from_str(&line).unwrap_or_else(|error| {
            let _ = child.wait();
            let mut stderr = String::new();
            if let Some(mut stream) = child.stderr.take() {
                let _ = stream.read_to_string(&mut stderr);
            }
            panic!("witness endpoint emitted invalid readiness ({error}): {stderr}");
        });
        let port = u16::try_from(ready["port"].as_u64().unwrap()).unwrap();
        Self {
            child,
            address: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fetch(address: SocketAddr, token: &str) -> Result<Vec<u8>, String> {
    let mut stream =
        TcpStream::connect_timeout(&address, REQUEST_TIMEOUT).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "GET /artifact HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(RESPONSE_BOUND + 4097).unwrap())
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    if boundary > MAX_HEADER_BYTES {
        return Err("endpoint headers exceed bound".into());
    }
    if !response.starts_with(b"HTTP/1.0 200 ") && !response.starts_with(b"HTTP/1.1 200 ") {
        return Err("endpoint refused request".into());
    }
    let body = response.split_off(boundary);
    if body.len() > RESPONSE_BOUND {
        return Err("endpoint response exceeds bound".into());
    }
    Ok(body)
}

fn fetch_with_fallback(endpoints: &[(&str, SocketAddr)], token: &str) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut providers = BTreeSet::new();
    for (provider, address) in endpoints.iter().take(MAX_ENDPOINT_ATTEMPTS) {
        providers.insert(provider);
        if providers.len() > 2 {
            return Err("endpoint provider bound exceeded".into());
        }
        if Instant::now() >= deadline {
            break;
        }
        if let Ok(bytes) = fetch(*address, token) {
            return Ok(bytes);
        }
    }
    Err("all bounded endpoint attempts failed".into())
}

fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

#[test]
#[allow(clippy::too_many_lines)]
fn isolated_http_endpoints_preserve_verification_and_fail_closed_faults() {
    let test_directory = TestDirectory::create();
    let directory = &test_directory.0;
    let certificate = fs::read("results/kubernetes-shadow-certificate.json").unwrap();
    let signer = SigningKey::from_bytes(&[71; 32]);
    let timestamp_key = SigningKey::from_bytes(&[72; 32]);
    let revocation_key = SigningKey::from_bytes(&[73; 32]);
    let attestation = attest_certificate(
        &certificate,
        "telosieve/research",
        "endpoint-lab",
        "signer-a",
        100,
        900,
        &signer,
    )
    .unwrap();
    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
    let verified = verify_attestation(
        &certificate,
        &attestation_bytes,
        &AttestationTrust {
            context: "telosieve/research".into(),
            evaluation_time: 700,
            keys: vec![AttestationKey {
                signer: "endpoint-lab".into(),
                key_id: "signer-a".into(),
                public_key: hex::encode(signer.verifying_key().to_bytes()),
                not_before: 50,
                not_after: 800,
            }],
        },
    )
    .unwrap();
    let timestamp = witness_attestation(
        &attestation_bytes,
        "telosieve/research",
        1,
        None,
        200,
        "timestamp-endpoint",
        "clock-a",
        &timestamp_key,
    )
    .unwrap();
    let timestamp_tip = timestamp.digest();
    let timestamp_bytes = serde_json::to_vec(&vec![timestamp]).unwrap();
    let revocation_bytes = serde_json::to_vec(
        &sign_revocations(
            "telosieve/research",
            1,
            600,
            800,
            vec![],
            "revocation-endpoint",
            "root-a",
            &revocation_key,
        )
        .unwrap(),
    )
    .unwrap();
    let trust = WitnessTrust {
        context: "telosieve/research".into(),
        evaluation_time: 700,
        timestamp_authority: "timestamp-endpoint".into(),
        timestamp_key_id: "clock-a".into(),
        timestamp_public_key: hex::encode(timestamp_key.verifying_key().to_bytes()),
        trusted_tip_sequence: 1,
        trusted_tip_digest: timestamp_tip,
        revocation_authority: "revocation-endpoint".into(),
        revocation_key_id: "root-a".into(),
        revocation_public_key: hex::encode(revocation_key.verifying_key().to_bytes()),
        trusted_revocation_sequence: 1,
        trusted_revocation_digest: hex::encode(Sha256::digest(&revocation_bytes)),
    };
    let timestamp_path = directory.join("timestamps.json");
    let revocation_path = directory.join("revocations.json");
    fs::write(&timestamp_path, &timestamp_bytes).unwrap();
    fs::write(&revocation_path, &revocation_bytes).unwrap();

    let timestamp_endpoint = Endpoint::start(&timestamp_path, TIMESTAMP_TOKEN, "normal", 0);
    let revocation_endpoint = Endpoint::start(&revocation_path, REVOCATION_TOKEN, "normal", 0);
    let fetched_timestamp = fetch(timestamp_endpoint.address, TIMESTAMP_TOKEN).unwrap();
    let fetched_revocation = fetch(revocation_endpoint.address, REVOCATION_TOKEN).unwrap();
    verify_witnessed_attestation(
        &verified,
        &attestation_bytes,
        &fetched_timestamp,
        &fetched_revocation,
        &trust,
    )
    .unwrap();

    drop(timestamp_endpoint);
    let restarted = Endpoint::start(&timestamp_path, TIMESTAMP_TOKEN, "normal", 0);
    assert_eq!(
        fetch(restarted.address, TIMESTAMP_TOKEN).unwrap(),
        timestamp_bytes
    );
    let unused = unused_address();
    assert_eq!(
        fetch_with_fallback(
            &[("timestamp-a", unused), ("timestamp-b", restarted.address)],
            TIMESTAMP_TOKEN,
        )
        .unwrap(),
        timestamp_bytes
    );

    let delayed = Endpoint::start(&timestamp_path, TIMESTAMP_TOKEN, "delay", 400);
    assert!(fetch(delayed.address, TIMESTAMP_TOKEN).is_err());
    let dropped = Endpoint::start(&timestamp_path, TIMESTAMP_TOKEN, "drop", 0);
    assert!(fetch(dropped.address, TIMESTAMP_TOKEN).is_err());
    assert!(fetch(restarted.address, "wrong-token").is_err());
    let oversized = Endpoint::start(&timestamp_path, TIMESTAMP_TOKEN, "oversized", 0);
    assert!(fetch(oversized.address, TIMESTAMP_TOKEN).is_err());
    assert!(fetch_with_fallback(&[("timestamp-a", unused)], TIMESTAMP_TOKEN).is_err());
    assert!(
        fetch_with_fallback(
            &[
                ("timestamp-a", unused),
                ("timestamp-b", unused),
                ("timestamp-c", unused),
            ],
            TIMESTAMP_TOKEN,
        )
        .is_err()
    );

    let equivocal_path = directory.join("equivocal.json");
    fs::write(&equivocal_path, b"{}").unwrap();
    let equivocal = Endpoint::start(&equivocal_path, TIMESTAMP_TOKEN, "normal", 0);
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &fetch(equivocal.address, TIMESTAMP_TOKEN).unwrap(),
            &revocation_bytes,
            &trust,
        )
        .is_err()
    );

    let stale = serde_json::to_vec(
        &sign_revocations(
            "telosieve/research",
            1,
            100,
            600,
            vec![RevokedSigner {
                signer: "endpoint-lab".into(),
                key_id: "signer-a".into(),
                revoked_at: 300,
            }],
            "revocation-endpoint",
            "root-a",
            &revocation_key,
        )
        .unwrap(),
    )
    .unwrap();
    let stale_path = directory.join("stale.json");
    fs::write(&stale_path, &stale).unwrap();
    let stale_endpoint = Endpoint::start(&stale_path, REVOCATION_TOKEN, "normal", 0);
    let mut stale_trust = trust;
    stale_trust.trusted_revocation_digest = hex::encode(Sha256::digest(&stale));
    assert!(
        verify_witnessed_attestation(
            &verified,
            &attestation_bytes,
            &timestamp_bytes,
            &fetch(stale_endpoint.address, REVOCATION_TOKEN).unwrap(),
            &stale_trust,
        )
        .is_err()
    );
}
