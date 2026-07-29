# Correlated Viability Faults

## Model

Distinct signing keys identify principals; they do not establish independent
failure. Certificate v3 therefore groups viability issuers into explicit trusted
fault domains. A viability hypothesis suspects one domain and excludes every
issuer assigned to it.

| Domain | Issuers | Intended independence |
|---|---|---|
| `lab-domain` | `viability-lab`, `viability-peer` | deliberately correlated |
| `review-domain` | `viability-review` | separate review authority |

Every viability issuer must have one non-empty domain when viability is
suspectable. Unknown issuers, missing or empty mappings, and mappings supplied
when viability is not suspectable fail before enumeration. Hypothesis count uses
unique domains rather than signer count and remains bounded by
`maximum_hypotheses`.

## Results

The weakened-viability fixture gives both `lab-domain` issuers the same weakened
rules while `review-domain` retains the strict epoch invariant. Under a one-domain
fault budget, Telosieve refuses with zero unsafe approvals. The benign fixture
still applies after excluding either domain, with zero false refusals.

The `all-viability-domains-weakened` fixture weakens both domains. With only one
domain declared faulty, every surviving rule set approves the poisoned
transition, producing one unsafe approval. This is an intentional retained
negative result: compromise or common semantic failure across all fault domains
is outside the registered bound and remains a productisation stop.

Raw observations are retained in `results/correlated-fault-benchmark.json`.

## Fault-domain requirements

An operator cannot satisfy independence by assigning different labels. A future
deployment would need evidence that domains have separate specification authors,
review paths, signing custody, implementation stacks, deployment control, and
incident blast radius. Shared policy generation, common administrators, copied
rules, or shared key custody collapse those principals into one fault domain.

The research harness authenticates the mapping as trusted scenario configuration;
it does not discover or attest organizational independence.

