# Sentinel Agent

**An execution gateway for AI agent tools.** Sentinel addresses a concrete failure: an agent reads attacker-controlled content and then requests access, export, or deletion outside its authority. The gateway authorizes the operation using trusted policy, independently of the model's explanation.

Status: functional local enforcement library with a SQLite document connector and adversarial replay lab. Not a deployed security service or universal defense against AI attacks. No live model integration or external connector is implemented yet.

## The problem

A support agent reads a poisoned document. It requests an export of payroll records to an attacker-controlled destination, or tries to delete documents claiming a manager approved it. Sentinel checks identity, tenant, tool grant, resource classification, destination clearance, and approval before executing the operation.

This does not require identifying whether the attacker was a human or an AI. It does require that actual tool execution pass through the gateway.

## Run the attack lab

Python 3.11+, no runtime dependencies, API keys, or network access needed:

```sh
python -m sentinel.attack_lab
python -m unittest discover -s tests -v
```

The lab replays eight scripted tool calls, including legitimate operations, cross-tenant access, unauthorized export, false approval, and classification spoofing. It checks both outcome and denial reason. This is a reproducible policy evaluation, not evidence of performance against a live attacking model.

## Implemented controls

| Control | Enforcement |
|---|---|
| Scoped identity | Host-minted bearer sessions bind tenant, tool grants, clearance, expiry and budget |
| Strict tool schemas | Unknown tools and extra arguments are rejected |
| Tenant isolation | Resource lookup uses session tenant, never model-supplied tenant |
| Sensitive data export | Trusted resource labels and destination clearances determine eligibility |
| Destination restriction | Export accepts only provisioned destination IDs; no arbitrary URLs |
| Destructive action review | Deletion needs an expiring, single-use approval bound to session, arguments and resource contents |
| Replay protection | Request IDs are persisted and checked transactionally |
| Bounded sessions | Denied calls also consume the session budget |
| Emergency stop | Persisted gateway switch denies subsequent operations |
| Atomic evidence | Local effects and audit records commit together or roll back together |

Exports create durable local outbox entries. They do not send network requests. Reads and approved deletes operate on the SQLite document store. This is enforcement for that connector; integrations must route actual tool execution through equivalent controls.

## Integration boundary

```text
Trusted application authenticates user and creates scoped session
                             |
Untrusted model produces tool name + arguments
                             |
Trusted host attaches session capability (never put in the prompt)
                             |
Sentinel validates -> authorizes -> executes local connector -> audits
                             |
Tool result returned as untrusted content
```

Only `Gateway.invoke` is an agent-facing entry point. Session creation, provisioning, approvals, destinations and the kill switch are trusted administrative operations. Python object visibility is not a sandbox: deploy separately from an agent that can execute arbitrary code.

See [integration and security boundaries](docs/GATEWAY.md).

## Tests

Tests cover permitted actions, forged identity, tenant spoofing, tool escalation, restricted exports, approval substitution/expiry/reuse, concurrent request replay, restart persistence, session expiry, budgets, and rollback when audit persistence fails. A poisoned-document scenario verifies that malicious text cannot change policy by itself.

## Earlier investigation prototype

```sh
python -m sentinel examples/demo.json --tenant demo-org
```

The original event investigator remains available. Its phrase matching is an illustrative detection signal, not the gateway's security boundary. See [its threat model](docs/THREAT_MODEL.md).

## Production work remaining

Authenticated service boundary, a real organization connector, approval identity integration, independent audit storage, operational quotas and monitoring, and live-agent adversarial evaluation. Network and model-output egress must be constrained to prevent bypass. No claim of production readiness or unique protection is implied.

References: [OWASP AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) and [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).
