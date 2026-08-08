# Security Policy

## Status and supported versions

Telosieve is evaluation software, not a production safety control. Until a public evaluation release is frozen, only the exact current signed evaluation candidate is eligible for security fixes. Historical candidates and arbitrary commits are unsupported.

## Reporting a vulnerability

Do not disclose a suspected vulnerability, exploit, credential, private assessment artifact, or affected operator identity in a public issue. For the private repository, use the evaluator channel agreed with the repository owner. After public opening, use GitHub's private vulnerability reporting entrypoint under the repository Security tab. If that entrypoint is unavailable, contact the repository owner through the contact method published on the owner's GitHub profile and wait for a private channel before sharing sensitive details.

Include the affected commit or tag, environment, minimal reproduction, observed and expected behavior, security impact, and whether target mutation or sensitive-data exposure occurred. Do not test against systems you do not own or have explicit permission to assess.

## Response process

The maintainer will acknowledge a usable report, reproduce it in an isolated environment, classify the affected claim and integration boundary, and coordinate remediation and disclosure. No response-time SLA is offered during evaluation. A credible unsafe approval, signature bypass, mutation-authority escape, credential disclosure, history rollback acceptance, or unbounded hostile-input path is stop-ship for an affected candidate.

Security fixes require the same local-CI, reviewed-PR, exact-candidate freeze, and reassessment process as other release-critical changes. Hosted CI is not part of the private-repository security boundary.
