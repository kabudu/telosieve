# Integration Contract v1

## Purpose and boundary

`telosieve.integration-contract/v1` is the stable extension boundary for new
read-only systems integrations. An integration is an external executable, not a
dynamic library loaded into the Telosieve process. It collects one bounded
desired/observed snapshot and has no authority to approve a repair, write
evidence, or mutate the target.

The stable evaluation mode is `external-read-only` with configuration schema
`telosieve.evaluation-config/v7`. Actuation is deliberately excluded. A future
actuator requires a separate versioned contract, authorization decision,
credential design, concurrency semantics, idempotency, recovery proof, and
independent assessment.

## Process protocol

Telosieve starts the configured absolute regular executable with at most 32
arguments of at most 4,096 non-control bytes. It writes one compact JSON request
to stdin, closes stdin, and accepts one response on stdout. The process has a
five-second deadline, 2 MiB stdout bound, and 16 KiB stderr bound. Failure,
timeout, malformed output, excess output, or a non-zero exit fails closed before
certificate or ledger persistence.

The configured executable is trusted not to daemonize or leave descendants
holding inherited stdout or stderr descriptors. Telosieve kills and reaps the
direct child on timeout, but the portable process contract does not claim to
contain a detached process tree. Run adapters in an OS-level sandbox or service
boundary when that assumption cannot be made.

The request is `telosieve.integration-request/v1`:

```json
{"schema_version":"telosieve.integration-request/v1","contract":"telosieve.integration-contract/v1","operation":"observe","integration_id":"example-service","resource_kind":"replicated-key-value","target_id":"example/service-a","subject":"kv/research","evaluation_time":1750000000}
```

The adapter must return canonical compact JSON matching
`telosieve.integration-response/v1`. Unknown fields, duplicate/non-canonical
shapes, partial state, empty identifiers, control characters, and structural
bounds refuse. [integration-response.example.json](../evaluation/integration-response.example.json)
is the complete example.

The response declares exactly:

- the configured integration, resource kind, target identity and a fresh target
  revision;
- the requested subject and exact evaluation time;
- capability contract `telosieve.integration-contract/v1`, operation `observe`,
  credential authority `read_only`, and `target_mutated: false`;
- `complete: true`;
- one desired key/value map and one observed replicated service state.

Telosieve independently requires the desired map and observed state to equal the
authenticated goal and phenotype authorities. It permits 1–64 replicas, at most
256 values per map, identifiers up to 128 restricted-ASCII bytes, and values up to
4,096 bytes. These generic shapes intentionally match the current bounded
replicated-service research model; integrations for other state models require a
new contract version rather than lossy translation.

## Corroboration and trust

The primary adapter response is not trusted by itself. Configuration v7 also
requires two to eight existing `telosieve.observation-source/v1` byte producers.
Every producer must independently return the exact response bytes and a valid
`external-read-only` attestation. Telosieve requires the configured
multi-domain quorum before parsing the response into a certificate.

Fault-domain labels do not create independent administration. Production-shaped
evaluation requires separate credentials, keys, processes, identities, hosts or
control planes as appropriate. The adapter executable and arguments are trusted
operator configuration and may themselves possess the declared read-only
credential; Telosieve cannot technically prevent a dishonest executable from
using separately available mutation credentials. Isolate and audit it.

## Configuration and output

[config.integration.example.json](../evaluation/config.integration.example.json)
shows every v7 field. Adapter and observation-source executables must be absolute
regular executable files. Scenario, trust, executables, configuration,
certificate, temporary certificate and ledger paths may not alias.

Success emits `telosieve.evaluation-report/v1` with mode
`external-read-only`, a decision, certificate digest and
`target_mutated: false`. Certificate v11 binds:

- contract, integration and resource-kind identifiers;
- target identity and revision;
- SHA-256 of the exact canonical adapter response; and
- the verified observation-quorum digest.

Both an applied decision and a Telosieve refusal are successful evaluations.
Protocol or persistence failure returns status 1 without a success report.
Certificate and ledger persistence retains the existing single-writer and
non-transactional cross-file limitations.

## Stable refusal taxonomy

Diagnostics begin with one of these contract codes:

| Code | Meaning |
|---|---|
| `integration.configuration` | Unsafe executable, arguments or identifiers |
| `integration.process` | Spawn, exit, timeout or stream failure |
| `integration.resource_bound` | Input, output or structural limit exceeded |
| `integration.malformed` | Invalid or unsupported response JSON |
| `integration.capability` | Mutation or non-read-only authority declared |
| `integration.context` | Subject, time, integration, resource or target mismatch |
| `integration.incomplete` | Collector cannot assert a complete observation |
| `integration.authority_mismatch` | Desired or observed state disagrees with signed authority |
| `integration.io` | Local adapter I/O failure |

Callers must treat the codes as categories, not parse the explanatory suffix.
No refusal should be repaired by weakening the response, quorum, time, size or
authority constraints.

## Conformance

Run:

```sh
cargo test --locked --offline --test integration_contract
```

The test drives the real CLI, stdin/stdout adapter protocol, two signed producer
envelopes, authority evaluation, certificate and ledger persistence. It also
requires mutation capability, incomplete collection, context substitution and
authority disagreement to fail without evidence.

`scripts/reference-integration-adapter.py` is a conformance fixture: it validates
the request and emits an operator-supplied response. It performs no platform
collection and is not a production integration.

An additional integration is conformant only when it also supplies platform-
specific parser tests, credential-scope evidence, outage/timeout behavior,
resource measurements, compromised-consistent-producer analysis, a disposable
real-system end-to-end qualification, and adversarial coverage entries. Passing
the generic fixture alone does not qualify a platform or establish truthful or
independent observations.

The first concrete conformance application is the bounded
[Redis Read-Only Integration](REDIS_INTEGRATION.md). Its real local ACL and
server qualification satisfies the platform-mechanics requirements while
retaining the independent-control-plane gate.
The second application is the transactionally coherent
[PostgreSQL Read-Only Integration](POSTGRESQL_INTEGRATION.md), with the same
independent-control-plane gate retained.
The third application is the fixed-GET
[HTTP/JSON Read-Only Integration](HTTP_JSON_INTEGRATION.md). Its local endpoint
qualification retains explicit TLS and independent-endpoint gates.
