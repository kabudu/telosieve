# Real Kubernetes End-to-End Qualification

`scripts/run-kubernetes-real-cluster.py` creates a uniquely named disposable
kind cluster using the pinned Kubernetes v1.36.1 node image digest. It applies a
three-replica StatefulSet, desired ConfigMap, forbidden Secret, and the
namespace-scoped evaluation Role. Telosieve receives only a ten-minute
service-account token and the real `kubectl` and API-server boundaries.

The harness requires successful evidence generation, an unchanged StatefulSet,
the documented read permissions, denial of mutation and Secret access,
fail-closed authority mismatch and API outage, completion within 120 seconds,
peak child RSS below 512 MiB, and unconditional cluster/credential cleanup.

Docker, kind, kubectl, and the pinned `kindest/node` image must already be
installed locally. The authoritative CI path does not silently download a
different node image.

This is a real local Kubernetes API server and real RBAC enforcement, but it is
still project-controlled evidence on one macOS/arm64 host. It does not qualify
EKS, GKE, AKS, other Kubernetes versions, multi-node behavior, sustained load,
credential plugins, admission controllers, network policy, upgrades, or an
independent operator.
