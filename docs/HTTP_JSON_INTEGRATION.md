# HTTP/JSON Read-Only Integration

Post-M51 provides a dependency-free HTTP/1.1 adapter for services that expose a
bounded Telosieve snapshot endpoint. It performs one fixed `GET`; it is not a
general-purpose REST client and has no mutation or redirect behavior.

Post-M52 adds explicit HTTPS with mutual TLS. HTTPS pins one configured CA,
requires hostname/IP verification and a client certificate, and fixes both the
minimum and maximum protocol version to TLS 1.3. Credential schema v2 also
requires an explicit CRL and enables leaf revocation checking. Each reader uses a distinct
client identity; there is no fallback to plaintext or the system trust store.

The endpoint returns `telosieve.http-json-snapshot/v1`:

```json
{"schema_version":"telosieve.http-json-snapshot/v1","revision":"revision-1","complete":true,"desired":{"key":"value"},"replicas":{"replica-a":{"key":"value"}}}
```

The adapter accepts only loopback endpoints in this qualification version. The
path is operator-configured but bounded to 256 visible ASCII bytes and cannot
contain a query or fragment. It sends `GET`, `Accept: application/json`,
`Connection: close`, and a bearer token read from an absolute owner-only,
regular, single-link credential file. HTTPS credentials also name the pinned
CA, client certificate and owner-only, regular, single-link client key. Token
and private-key bytes never appear in process arguments, diagnostics, or
retained evidence.

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
python3 scripts/http-json-pki-check.py --openssl /absolute/path/to/openssl --credentials /absolute/path/to/credentials.json
```

The harness starts a real loopback HTTP server and exercises the public v7 CLI,
one primary adapter, two separately signed producer processes, three bearer
identities, eight evaluations at concurrency four, and denial of POST, PUT,
PATCH and DELETE over both HTTP and mutual TLS. The HTTPS phase uses an
ephemeral CA, server identity and three client identities with TLS 1.3. Nineteen
combined faults cover the original protocol cases plus wrong CA, missing or
untrusted client identity, plaintext downgrade, producer disagreement, timeout
and outage. It additionally proves a client-identity rotation succeeds, a
revoked server is refused, and missing or malformed CRLs fail closed. The retained result is
[`http-json-integration-qualification.json`](../results/http-json-integration-qualification.json).

The offline PKI readiness command verifies CA trust, CRL signature and renewal
horizon, client purpose/revocation, certificate expiry and key pairing. Its JSON
report contains no paths, certificate contents, tokens or private-key material.

This is an orchestrated endpoint qualification, not external evidence. It
qualifies local TLS 1.3/mTLS mechanics but not DNS, proxies, service meshes,
OAuth refresh, public networks,
vendor rate limits, independently administered endpoints, credential custody,
or truthful producers. Production use requires audited operational PKI,
independent endpoints and keys,
rotation/revocation procedures, topology-specific load testing, and independent
assessment. No HTTP mutation method is authorized.
