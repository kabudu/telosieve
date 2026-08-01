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

`http-json-pki-monitor.py` runs one to four readiness checks, publishes one
owner-only aggregate status atomically, returns nonzero when any identity is not
ready, and never copies checker diagnostics into the status. The packaged
systemd service and timer run it every 15 minutes under a dedicated user with
network access disabled. Kubernetes operators can run the same scheduler-neutral
command from their privately built evaluator image; no nonexistent public image
is claimed here.

The monitor configuration is a non-secret regular JSON file that is not writable
by group or other users:

```json
{"schema_version":"telosieve.http-json-pki-monitor/v1","checker":"/usr/local/lib/telosieve/http-json-pki-check.py","openssl":"/usr/bin/openssl","credentials":["/etc/telosieve/adapter-mtls.json","/etc/telosieve/producer-a-mtls.json","/etc/telosieve/producer-b-mtls.json"],"renew_before_seconds":604800}
```

Install the common module, checker and monitor together under
`/usr/local/lib/telosieve`, create the `telosieve-pki-monitor` system user and
an owner-only `/var/lib/telosieve`, install both packaged units under
`/etc/systemd/system`, then run `systemd-analyze verify` and enable
`telosieve-http-json-pki-monitor.timer`. The monitor user needs read access to
the credentials and PKI files but no network access or target mutation authority.

Create owner-writable `/var/lib/telosieve/prometheus` for the monitor user and
configure Prometheus Node Exporter's textfile collector to read that directory.
Published metrics are non-secret `0644` files and reject group/other writes. The service
runs `http-json-pki-prometheus.py` after every monitor attempt. It publishes six
fixed-cardinality gauges, rejects status older than 20 minutes or more than 60
seconds in the future, and exits nonzero unless the source is valid, fresh and
fully ready. Monitor failure is deliberately ignored only until the publisher
converts missing, stale or malformed status into non-ready metrics and a failed
unit. Alert when any validity gauge differs from one or the timestamp leaves the
same freshness window:

```promql
telosieve_http_json_pki_source_valid != 1 or telosieve_http_json_pki_fresh != 1 or telosieve_http_json_pki_ready != 1 or time() - telosieve_http_json_pki_status_checked_unixtime_seconds > 1200 or time() - telosieve_http_json_pki_status_checked_unixtime_seconds < -60
```

The metrics contain no labels, paths, certificate values or checker diagnostics.
The operator must independently configure Prometheus scraping, alert routing,
retention and on-call ownership; packaging the publisher is not evidence that
those controls exist.

This is an orchestrated endpoint qualification, not external evidence. It
qualifies local TLS 1.3/mTLS mechanics but not DNS, proxies, service meshes,
OAuth refresh, public networks,
vendor rate limits, independently administered endpoints, credential custody,
or truthful producers. Production use requires audited operational PKI,
independent endpoints and keys,
rotation/revocation procedures, topology-specific load testing, and independent
assessment. No HTTP mutation method is authorized.
