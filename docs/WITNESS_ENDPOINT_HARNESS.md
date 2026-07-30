# Isolated witness endpoint harness

Date: 2026-07-30

## Scope and claim

Post-M24 is a production-shaped local integration harness. Timestamp and
revocation artifacts are served by separate project-controlled Python processes
over real loopback HTTP. The processes have distinct immutable artifact files
and fixture bearer credentials. They cannot mutate Telosieve state.

This is process, storage, credential, and transport isolation. It is not
organizational independence, third-party administration, production identity,
or independent assessment.

## End-to-end boundary

The Rust harness generates real signed certificate, attestation, timestamp, and
revocation artifacts through existing APIs. It starts the endpoint processes,
fetches their bytes through a dependency-free HTTP client, then passes the
fetched bytes through the existing exact-digest, Ed25519, timestamp-chain,
revocation, and trusted-tip verifier. HTTP 200 alone never authorizes evidence.

Each request is capped at 250 ms, headers at 4 KiB, bodies at 64 KiB, providers
at two, attempts at three, and a scenario at two seconds. Authentication failure,
malformed transport, timeout, connection loss, oversize, unavailable providers,
or verification failure refuses without cached or unsigned fallback.

## Retained fault matrix

`./scripts/run-witness-endpoint-harness.sh` retains ten live cases:

- healthy exact artifacts, authenticated process restart, and one-sided
  partition fallback succeed;
- delayed response, dropped connection, wrong credential, oversized body,
  total outage, equivocal artifact, and stale revocation refuse.

Every process is killed and reaped by RAII cleanup; temporary files are removed
after the scenario. Endpoint files are read once at process start, so restart
tests exercise persisted immutable bytes rather than shared in-memory state.

## Residual limits

Transport is loopback HTTP without TLS because all processes run on one trusted
development host. Tokens and private keys are deterministic fixtures. The
harness does not exercise DNS, certificates, TLS rotation, proxies, hostile
networks, kernel network namespaces, multiple machines, real clock drift,
production secrets, endpoint admission controls, load, or operator incident
response. Post-M25 remains the independently administered reproduction gate.
