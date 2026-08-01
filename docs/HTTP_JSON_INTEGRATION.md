# HTTP/JSON Read-Only Integration

Post-M51 provides a dependency-free HTTP/1.1 adapter for services that expose a
bounded Telosieve snapshot endpoint. It performs one fixed `GET`; it is not a
general-purpose REST client and has no mutation or redirect behavior.

The endpoint returns `telosieve.http-json-snapshot/v1`:

```json
{"schema_version":"telosieve.http-json-snapshot/v1","revision":"revision-1","complete":true,"desired":{"key":"value"},"replicas":{"replica-a":{"key":"value"}}}
```

The adapter accepts only loopback endpoints in this qualification version. The
path is operator-configured but bounded to 256 visible ASCII bytes and cannot
contain a query or fragment. It sends `GET`, `Accept: application/json`,
`Connection: close`, and a bearer token read from an absolute owner-only,
regular, single-link credential file. Tokens never appear in process arguments,
diagnostics, or retained evidence.

Responses require status 200, exact JSON media type, a numeric `Content-Length`
no greater than 2 MiB, complete delivery, strict JSON without duplicate keys,
and the Integration Contract v1 map/identity/value bounds. The socket deadline
is one second. Redirects, chunked/lengthless responses, authentication failure,
timeouts, malformed or excess data, and incomplete snapshots fail before
certificate or ledger persistence.

Run:

```sh
cargo build --locked --offline
python3 scripts/test-http-json-integration.py
python3 scripts/run-http-json-integration.py
```

The harness starts a real loopback HTTP server and exercises the public v7 CLI,
one primary adapter, two separately signed producer processes, three bearer
identities, eight evaluations at concurrency four, and denial of POST, PUT,
PATCH and DELETE. Eight faults cover redirect, malformed and oversized bodies,
incomplete state, timeout, authentication refusal, producer disagreement, and
outage. The retained result is
[`http-json-integration-qualification.json`](../results/http-json-integration-qualification.json).

This is an orchestrated endpoint qualification, not external evidence. It does
not qualify TLS, DNS, proxies, service meshes, OAuth refresh, public networks,
vendor rate limits, independently administered endpoints, credential custody,
or truthful producers. Production use requires an audited TLS-capable transport
boundary or mutually authenticated local proxy, independent endpoints and keys,
rotation/revocation procedures, topology-specific load testing, and independent
assessment. No HTTP mutation method is authorized.
