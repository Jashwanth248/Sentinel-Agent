# Sentinel Agent

An early foundation for an organization security investigation agent, covering identity events and activity involving AI agents.

**Status: offline, rule-based prototype.** No live LLM, production integrations, authenticated service, or automated containment is implemented. This is not a replacement for endpoint protection, a SIEM, or a security team.

## Run the demo

Python 3.11 or newer; no runtime dependencies or API keys required.

```sh
python -m sentinel examples/demo.json --tenant demo-org
python -m unittest discover -s tests -v
```

Run from the repository directory. The demo produces four findings with source event IDs: a successful login following five failures within ten minutes, an administrative grant, a tool call outside the allowlist, and suspicious text in retrieved content. Findings require analyst review and do not establish compromise. Reports are written to standard output; redirect to a protected local file if needed.

## What works

- Validates and orders timestamped JSON events with explicit tenant scope.
- Correlates failed and successful logins for the same actor.
- Flags administrative grants for review.
- Identifies agent tool names outside a fixed allowlist.
- Flags a few suspicious instruction phrases as weak investigation signals.
- Produces structured JSON findings with evidence references.
- Rejects duplicate event IDs and oversized input.

The tool allowlist is a policy example; there is no tool executor. Detecting an event does not block the external system that generated it. Tenant filtering is not an authentication boundary. Input text is never executed or sent to an external model.

## Event format

Input is a JSON array. Each in-scope event requires nonempty string fields `id`, `tenant`, `actor`, `type`, and `timestamp` (ISO 8601 with timezone). Supported event types are `login_failed`, `login_success`, `privilege_granted` (with `role`), `agent_tool_call` (with `tool`), and `retrieved_content` (with `content`). Unknown types are counted but produce no findings. Maximum input: 5 MB and 10,000 events. See `examples/demo.json`.

## Proposed production architecture

```text
Identity / cloud / endpoint / AI gateway events
                    |
         Authenticated ingestion + normalization
                    |
       Tenant-scoped evidence store + detections
                    |
       Bounded investigation + optional LLM summary
                    |
         Analyst review + independent policy service
                    |
       Approved connector action + audit + verification
```

Only local normalization and example detections are implemented today. Model output must remain advisory; external authorization must govern tool execution. A future model integration needs a selected provider, data-handling agreement, redaction, evidence validation, and adversarial evaluation before real organization data is sent.

## Roadmap

1. Authenticated ingestion and one read-only identity connector.
2. Durable evidence storage, access controls, retention, and audit logging.
3. Optional model-assisted investigation with source validation and strict budgets.
4. Historical incident evaluation and prompt-injection testing.
5. Analyst interface and approval workflow.
6. Narrow containment integrations with independently enforced permissions.

See `docs/THREAT_MODEL.md` and `SECURITY.md` for boundaries and deployment prerequisites.
