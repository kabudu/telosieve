# Observation Producer Isolation Kit

## Boundary

The evaluator normally executes observation sources as direct child processes,
which cannot cross Linux user identities without privilege. The M42 kit adds an
authenticated local Unix-stream boundary: the evaluator executes
`observation-source-client.py`; a long-running `observation-source-relay.py`
under a distinct systemd user performs one fresh producer execution and returns
its exact stdout. No observation is cached or written by the relay.

Deploy one relay instance, service user, client group, token, signing key,
platform credential, and configuration per producer. The evaluator account may
join each `telosieve-observation-INSTANCE-client` group. A producer account must
not join another producer's client group. This keeps producer signing keys and
platform credentials unreadable by the evaluator and peer producers while
allowing the evaluator to request a fresh observation.

## Linux installation

Install the bundled relay, client, and platform producer programs under
`/opt/telosieve/scripts` with owner `root:root` and mode `0555`. Install
`deploy/systemd/telosieve-observation@.service` under `/etc/systemd/system` with
mode `0444`. For an instance such as `opentofu-a`:

1. Create user `telosieve-observation-opentofu-a` and group
   `telosieve-observation-opentofu-a-client`, with no login shell.
2. Add only the evaluator account and that producer account to the client group.
3. Store a random 32–128 byte token at
   `/etc/telosieve/tokens/opentofu-a.token`, owned by
   `root:telosieve-observation-opentofu-a-client`, mode `0440`.
4. Store the signing key and platform material under
   `/var/lib/telosieve-observation-opentofu-a`, owned by the producer account,
   with directory mode `0700` and key mode `0400`.
5. Copy and review `deploy/systemd/observation-opentofu-a.example.json` as
   `/etc/telosieve/observation-opentofu-a.json`, owned by root and readable by
   the producer account. Replace fixture times, identities, paths, and public
   trust material together.
6. Run `systemd-analyze verify telosieve-observation@.service`, then enable and
   start `telosieve-observation@opentofu-a.service`.
7. Repeat with a different user, client group, token, key, platform credential,
   and fault domain for the second producer.

The Kubernetes example follows the same procedure and additionally needs only
its named read-only kubeconfig/RBAC scope. Never grant a producer mutation
credentials or access to another producer's key, token, kubeconfig, saved plan,
or configuration.

## Resource, failure, and logging behavior

The relay accepts four queued connections and handles one request at a time,
providing bounded backpressure instead of unbounded fan-out. Authentication is
constant-time over a 32–128 byte token. Each producer execution has a five-second
deadline, 5 MiB stdout, 16 KiB stderr, 32 arguments, and 4,096 bytes per
argument. The client has a six-second deadline and 5 MiB response bound.
Unauthorized, empty, failed, timed-out, or oversized responses fail closed.
Configuration and socket directories reject group/other write access; clients
reject symlinked or non-socket endpoints.
`observation-source-client.py --socket PATH --token PATH --check` performs an
authenticated readiness check without executing the producer or returning an
observation.

The systemd profile applies `NoNewPrivileges`, read-only system paths, private
devices and temporary storage, namespace/kernel restrictions, a 32-task limit,
256 MiB memory limit, bounded start/stop, and five-second restart backoff.
Standard output is discarded because it can contain the complete observation.
Producer stderr is bounded and discarded; the journal receives only generic
relay/service failures and must never receive observation content. A clean stop
removes only the relay's own socket. Restart removes an owned, inactive stale
socket but refuses an active or foreign path.

## Qualification and limitations

Run `python3 scripts/run-producer-isolation-qualification.py`. The local harness
proves non-sensitive readiness, exact authenticated relay output, stale-socket
restart, socket mode `0660`, token and symlink refusal,
producer failure/timeout/output bounds,
unsafe-token/configuration refusal, cleanup, and systemd hardening drift. It
runs under one local UID and does not execute
systemd, Linux user separation, real credential isolation, host separation, or
independent administration. Those require a Linux operator exercise and remain
external promotion gates. Tokens authenticate local requests; they do not make
producer observations truthful or organizationally independent.

`scripts/run-opentofu-plan.py` additionally routes the real two-producer
OpenTofu success lifecycle through two live relays and the stable evaluation
CLI. Kubernetes relay operation uses the same envelope transport, but the real
cluster harness still invokes its producer processes directly; real systemd and
multi-UID Kubernetes qualification remains open.
