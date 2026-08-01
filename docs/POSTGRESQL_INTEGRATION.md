# PostgreSQL Read-Only Integration

Post-M50 maps four fixed tables in one PostgreSQL schema into Integration
Contract v1. It is a read-only evaluation adapter, not a SQL repair engine.

| Table | Required columns | Mapping |
|---|---|---|
| `metadata` | `singleton`, `revision` | exact target revision |
| `desired` | `key`, `value` | authenticated desired values |
| `replicas` | `replica_id` | observed replica identities |
| `observed` | `replica_id`, `key`, `value` | each replica's values |

The adapter invokes an absolute, non-writable `psql` executable with a fixed SQL
program. It begins one `REPEATABLE READ READ ONLY` transaction, sets one-second
statement and 500 ms lock deadlines, materializes only bounded rows, validates
identifier/value limits, caps aggregate payload bytes at 1.5 MiB, and emits one
JSON snapshot. Limits are one metadata row, 256 desired values, 64 replicas,
256 values per replica and 16,384 observed rows. PostgreSQL errors, locks,
timeouts, excess rows, malformed output and incomplete state fail before
Telosieve evidence persistence.

Credentials use an absolute owner-only, regular, single-link JSON file:

```json
{"schema_version":"telosieve.postgresql-credentials/v1","username":"telosieve_reader","password":"replacewithrandomalphanumericsecret"}
```

The password is copied only into an ephemeral `0600` pgpass file inside a `0700`
temporary directory, is never placed in process arguments or environment
values, and is removed when `psql` exits. The subprocess receives a sanitized
environment, `--no-psqlrc`, a one-second connection timeout, fixed output/error
bounds and a three-second process deadline.

The role should receive only database `CONNECT`, schema `USAGE`, and `SELECT` on
the four fixed tables, with `default_transaction_read_only=on`. The disposable
qualification creates three such roles and proves denial of `INSERT`, `UPDATE`,
`DELETE`, `CREATE TABLE`, `DROP TABLE`, and a read from an ungranted secret
schema.

Run:

```sh
cargo build --locked --offline
python3 scripts/test-postgresql-integration.py
python3 scripts/run-postgresql-integration.py
```

The real-system harness uses PostgreSQL 18.4 pinned at
`postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`
and local libpq 18.1. The container runs as UID/GID 70 with a read-only root,
capabilities dropped, no-new-privileges, bounded CPU/memory/PIDs, and disposable
tmpfs data. It exercises one success, eight evaluations at concurrency four,
four evaluations during committed writer races, and no-evidence refusal for
unsafe/revoked credentials, 65 replicas, signed producer disagreement, stale
producer timing, an exclusive-lock timeout, and complete outage. Cleanup is
bounded and the container uses `--rm`.

The retained result is
[`postgresql-integration-qualification.json`](../results/postgresql-integration-qualification.json).
Timings are one-host observations, not service objectives.

All three readers still share one database, host, administrator, schema and
project-controlled harness. Production evaluation additionally requires
separate control planes and custody, protected remote transport, supported
topology/version matrices, failover/recovery testing, credential rotation,
larger-scale measurement and independent assessment. No PostgreSQL mutation or
actuation path is authorized.
