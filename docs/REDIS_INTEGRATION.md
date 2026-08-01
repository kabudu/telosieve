# Redis Read-Only Integration

## Scope

Post-M49 is the first concrete implementation of
`telosieve.integration-contract/v1`. It maps a bounded Redis key namespace to
Telosieve's replicated key/value research model and has no write or actuation
path. The included qualification uses a pinned disposable Redis 8.8 server on
loopback; it is integration evidence, not an independently administered or
production Redis deployment.

## Data mapping

For a configured prefix such as `telosieve:qualification`, the adapter reads:

| Redis key | Type | Telosieve field |
|---|---|---|
| `<prefix>:revision` | string | target revision |
| `<prefix>:desired` | hash | desired values |
| `<prefix>:replicas` | set | replica identifiers |
| `<prefix>:replica:<id>` | hash | each observed replica's values |

The collector accepts 1–64 replicas, at most 256 fields per hash, 128-byte
restricted-ASCII identifiers, 4,096-byte values, and at most 2 MiB total Redis
response traffic. It discovers at most 64 replica names, then atomically
re-reads the replica set, revision, desired hash and every replica hash inside
one read-only `MULTI`/`EXEC` transaction. Set drift, queue failure or an
incomplete transaction refuses. It performs at most 70 commands after
authentication, uses a one-second connect/read timeout, and supports only literal loopback
endpoints in this version. Empty/incomplete state, duplicate identities,
unsupported RESP types, Redis errors, malformed lengths and exceeded bounds
fail before Telosieve writes evidence.

## Credentials and authority

Credentials are supplied through an absolute, owner-only, regular, single-link
JSON file, never command-line secrets:

```json
{"schema_version":"telosieve.redis-credentials/v1","username":"telosieve-reader","password":"replace-with-a-random-secret"}
```

The Redis ACL user should be limited to the configured namespace and these
commands:

```text
~telosieve:qualification:* +get +hgetall +smembers +ping +multi +exec
```

The qualification creates separate ACL users for the primary adapter and both
observation producers and proves that `SET` returns `NOPERM` for each. This is
a real technical credential-scope check. All users still share one Redis server,
host, administrator and project-controlled harness, so their configured fault
domains do not establish independent administration or producer truth.

## Qualification

Build Telosieve and run:

```sh
cargo build --locked --offline
python3 scripts/test-redis-integration.py
python3 scripts/run-redis-integration.py
```

The real-system harness requires Docker and the pinned image already present:

```text
redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005
```

It starts a read-only, capability-dropped, resource-limited container with a
random loopback port, seeds state through a separate administrator, evaluates
through the public CLI, verifies certificate v11, and runs eight evaluations at
concurrency four. It additionally requires read-credential mutation attempts,
unsafe credential permissions, 65-replica input, one producer's divergent
snapshot, a stale producer attestation, and complete Redis outage to fail
without certificate or ledger output. Cleanup runs in `finally`; the
container uses `--rm` and no persistent volume.

The retained local result is
[`redis-integration-qualification.json`](../results/redis-integration-qualification.json).
Its timings are observations from one host, not service-level objectives.

## Remaining production gates

A production Redis evaluation still requires separate hosts/control planes,
independent credential custody and signing keys, TLS or a protected local
transport beyond loopback, version/topology coverage, failover and resharding
semantics, production-scale measurements, secret rotation, operational
monitoring, and independent assessment. This adapter does not authorize Redis
writes, repair execution, or promotion of the current signed release candidate.
