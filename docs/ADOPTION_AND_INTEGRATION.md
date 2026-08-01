# Adoption and Integration

The first supported evaluation shape is a private read-only sidecar. The current
offline simulator, exported Kubernetes snapshot, and live least-privilege
collector establish its input and decision boundaries.
JSON authority envelopes enter through bounded interfaces; decisions leave as
JSON and an append-only log. Telosieve must not receive mutation credentials.

The first shadow-mode adapter now maps bounded exported Kubernetes ConfigMap and
StatefulSet evidence without API access or actuation. Promotion requires zero unsafe approvals in the
pre-registered adversarial suite, reproducible refusal behavior, and an operator
escape hatch. Existing GitOps/reconciler systems remain the execution plane;
Telosieve is an evidence gate, not a replacement.

The certificate-v8 local reference actuator now exercises actual durable state
change behind the gate. It is deliberately file-backed so service mutation,
history advancement, and deletion consumption can share one atomic replacement.
An external adapter must offer equivalent compare-and-commit semantics or a
recovery protocol that preserves at-most-once effects; a blind API call after
certificate generation is insufficient.

Compatibility risks include schema drift, clock assumptions, identity/key
rotation, and semantic mismatch between declared invariants and platform behavior.
See [KUBERNETES_SHADOW](KUBERNETES_SHADOW.md).

Evaluation adoption now has a versioned CLI/configuration contract plus
documented and qualified single-host lifecycle operations plus content-redacted
diagnostics. Reproducible private artifacts, resource/recovery qualification,
and an operator escape hatch remain candidate work. Independent validation targets the exact
candidate after these capabilities exist. Production integration remains a
separate promotion decision.

OpenTofu is the second testable external integration. Its plan-only adapter
provides a provider-neutral evaluation boundary using `terraform_data`, with the
exact plan bound into certificate v10. External providers, remote state, and any
apply workflow remain outside the qualified boundary.

Redis is the first concrete implementation of the standardized external
read-only contract. A bounded namespace maps into the current replicated
key/value model, while separate Redis ACL users constrain the primary adapter
and two signed producers to read commands. The local qualification proves
technical mutation denial but shares one host and server; remote transport,
cluster topology, independent custody and production operation remain open.
