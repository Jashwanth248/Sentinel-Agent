# Threat model and deployment gates

## Protected assets

Organization telemetry, identities, credentials, customer boundaries, investigation integrity, and eventual response privileges.

## Trust boundaries

Log content, retrieved documents, repository content, and model outputs are untrusted. The current CLI trusts its operator and input file location. It is not safe to expose as a multi-user service without authentication and storage isolation. A caller-supplied tenant value must never serve as proof of authorization.

## Threats and current behavior

| Threat | Current behavior | Remaining work |
|---|---|---|
| Prompt injection | Text remains data; no model or executor | Adversarial model testing and tool gateway enforcement |
| Unauthorized tool use | Unknown tool names yield findings | Actual authenticated gateway interception |
| Cross-organization access | Local filtering only | Identity-bound scope, isolated storage, access tests |
| Evidence poisoning | Duplicate IDs rejected | Authenticated sources, provenance, tamper detection |
| Resource exhaustion | File and event limits | Request quotas, per-tenant budgets, latency limits |
| False positives / missed attacks | Findings explicitly need review | Labeled evaluation corpus and monitored precision/recall |

Phrase matching cannot reliably detect prompt injection. Attackers may paraphrase or encode instructions. The architecture must remain safe even when detection fails. AI authorship of an attack cannot be established from these events.

## Before production

Require a security design review, authentication and authorization testing, secret management, tenant isolation, ingestion integrity, encrypted storage, retention policies, operational monitoring, backup recovery tests, and an incident owner. Evaluate with benign events and known incidents. For response actions, add independent authorization, approver identity, action expiry, idempotency, blast-radius limits, verification, and an emergency stop. None of these production assurances are implied by passing the prototype tests.

References: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html and https://www.nist.gov/cyberframework
