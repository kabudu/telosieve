# Adoption and Integration

The first integration is an offline sidecar around a deterministic key-value
simulator. JSON authority envelopes enter through files; decisions leave as JSON
and an append-only log. No cluster credentials are required.

Later, a shadow-mode adapter may observe Kubernetes-style desired and observed
state without actuation. Promotion requires zero unsafe approvals in the
pre-registered adversarial suite, reproducible refusal behavior, and an operator
escape hatch. Existing GitOps/reconciler systems remain the execution plane;
Telosieve is an evidence gate, not a replacement.

Compatibility risks include schema drift, clock assumptions, identity/key
rotation, and semantic mismatch between declared invariants and platform behavior.
