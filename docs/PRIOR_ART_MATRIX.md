# Prior-Art Matrix

| Work | Established capability | Overlap | Remaining distinction to test |
|---|---|---|---|
| [Rainbow](https://www.cs.cmu.edu/~able/publications/computer04/) | Architecture-based adaptation | model/plan/execute loop | desired state can itself be a fault hypothesis |
| [Models@run.time](https://arxiv.org/abs/1505.00903) | Runtime models for adaptation | explicit live models | provenance-separated adversarial authorities |
| [Runtime verification for changing requirements](https://arxiv.org/abs/2303.16530) | Monitor evolving requirements | requirements may change | exclude suspected goal; cross-hypothesis approval |
| [IRM-SA](https://doi.org/10.1016/j.jss.2016.02.028) | Invariant-based self-adaptation | viability constraints | independent authority and poisoned-intent case |
| [Defective requirements in self-healing](https://doi.org/10.19153/cleiej.10.2.5) | Requirement defects affect repair | intent can be defective | operational provenance protocol and refusal |
| [Specification-language diversity](https://doi.org/10.1016/S0164-1212%2801%2900127-3) | Diversity reduces common faults | independent specifications | three authority roles plus hypothesis exclusion |
| [N-version experiment](https://libraopen.library.virginia.edu/entities/publication/4ac33eeb-79b4-46e4-aef9-f6ec56a62286) | Correlated independent failures | warns against independence assumptions | measurable checker separation |
| [Kubernetes self-healing](https://kubernetes.io/docs/concepts/architecture/self-healing/) | Desired/observed reconciliation | production baseline | distrust desired state |
| [CockroachDB tenant zone-config RFC](https://github.com/cockroachdb/cockroach/blob/master/docs/RFCS/20210610_tenant_zone_configs.md) | poisoned config may block reconciliation | poisoned configuration concern | no multi-authority hypothesis protocol |
| US8082471 / US8892702 | Policy-driven autonomic repair patents | adaptive remediation | claims require counsel review |
| US9372742 / US10705916 | Resilient orchestration/recovery patents | recovery control | claims require counsel review |
| WO2022140072 / US10938667 | Integrity/recovery-related patents | evidence and remediation | claims require counsel review |

Search classes used on 2026-07-29: poisoned/corrupt desired state, defective
requirements self-healing, adversarial reconciliation, multi-authority repair,
runtime invariants, diverse specifications, Byzantine control plane, and patents
on autonomic remediation. Databases included general web, Google Scholar/arXiv
landing pages, publisher pages, GitHub, package registries, and Google Patents.
This matrix must be refreshed claim-by-claim before publication or investment.
