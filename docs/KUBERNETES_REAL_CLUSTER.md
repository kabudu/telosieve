# Real Kubernetes End-to-End Qualification

`scripts/run-kubernetes-real-cluster.py` creates a uniquely named disposable
kind cluster using the pinned Kubernetes v1.36.1 node image digest. It applies a
three-replica StatefulSet, desired ConfigMap, forbidden Secret, and the
namespace-scoped evaluation Role. Telosieve receives only a ten-minute
service-account token and the real `kubectl` and API-server boundaries.

Post-M44 invokes two producer processes through separate authenticated Unix
relays per evaluation. Each relay serializes and bounds requests to a producer;
each producer performs its own four Kubernetes reads, canonicalizes the
snapshot, and signs it with a separate synthetic owner-only key in a distinct
configured fault domain. The evaluator receives only relay client paths and
tokens. The primary collector and both producer snapshots must agree exactly
before certificate persistence. Producer keys remain in the disposable harness
directory and never enter Telosieve evaluation configuration or evidence.

The harness requires successful evidence generation, an unchanged StatefulSet,
the documented read permissions, denial of mutation and Secret access,
fail-closed authority mismatch, API outage, and relay outage, completion within 120 seconds,
peak child RSS below 512 MiB, and unconditional cluster/credential cleanup.

Docker, kind, kubectl, and the pinned `kindest/node` image must already be
installed locally. The authoritative CI path does not silently download a
different node image.

This is a real local Kubernetes API server and real RBAC enforcement, but it is
still project-controlled evidence on one macOS/arm64 host. It does not qualify
EKS, GKE, AKS, other Kubernetes versions, multi-node behavior, extended load,
credential plugins, admission controllers, network policy, upgrades, or an
independent operator.
Both producers still use the same disposable cluster, API endpoint, local host,
project-controlled script, and credential. This proves process/envelope/quorum
integration and detects injected single-producer disagreement in the harness;
it does not prove independent control planes or organizations.

Post-M35 adds eight evaluations at four-way concurrency against the same real
API server under a five-second per-evaluation timeout and 30-second load-phase
bound. Post-M44 routes all of them through the two serial, backlog-bounded
relays. All use distinct evidence outputs, the least-privilege credential, and
preserve the target UID, resource version, and generation. This bounded sample
is not a capacity or managed-cluster claim;
see [SUSTAINED_ADVERSARIAL_LOAD](SUSTAINED_ADVERSARIAL_LOAD.md).
