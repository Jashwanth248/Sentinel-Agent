# Tool gateway integration and limits

## Local integration

```python
from sentinel.gateway import Gateway

gateway = Gateway('local.db')
# Trusted host operations, after host-side authentication:
gateway.put_document('acme', 'guide', 'Internal handbook', 'internal')
gateway.add_destination('acme', 'review-queue', 'internal')
session = gateway.create_session(
    'acme', 'support-agent', ['read_document', 'export_document'],
    clearance='internal', ttl=300, budget=20,
)
# Untrusted model output has only these fields:
call = {'id': 'call-1', 'tool': 'export_document',
        'arguments': {'document_id': 'guide', 'destination': 'review-queue'}}
result = gateway.invoke(session, call)
assert result['outcome'] == 'allowed'
assert result['result']['delivery'] == 'queued_locally'
gateway.close()
```

The host retains the capability privately and attaches it outside model arguments. Never expose administrative methods or the database to the agent. Actor and approver identities are trusted host assertions; this library does not authenticate people.

## Approval flow

The trusted host presents exact deletion arguments and the current document to an authenticated approver. It calls `gateway.approve(session, call, approver=verified_identity)` only after approval, then passes the returned token to `invoke(..., approval_token=token)`. Approval binds the session, tool, arguments and resource contents, expires within five minutes, and is consumed atomically with deletion. It cannot override clearance. If a request was denied, use a fresh request ID for the approved attempt.

## Connector guarantees

Resources and destinations are scoped to the session tenant. Public, internal and confidential classifications are trusted provisioning data. Export accepts references, not arbitrary model-generated text or URLs. Local operations, replay state and audit writes are serialized with SQLite transactions. Audit failure rolls back local changes and propagates an exception; the host must fail closed.

Audit records contain hashes of sessions, request IDs and commands plus outcomes and reasons. They omit document bodies and bearer tokens. They are local records, not tamper-proof forensic evidence.

## Outside the boundary

- **Bypass:** an agent with its own shell, network, files or credentials can avoid the library. Separate process/service and OS/network controls are required.
- **Model-output leaks:** authorized reads reveal content to the caller. This does not stop a model from repeating it to a user or external model provider. Output egress and provider policy require separate controls.
- **Host compromise:** administrative methods can change policy. Session minting and approvals need authenticated, authorized host infrastructure.
- **Abuse within permission:** valid access can still be abused. Least privilege, correct classification, monitoring and investigation remain necessary.
- **Availability:** budgets are per session, not global ingress limits. Invalid-identity traffic can grow audit storage. APIs need request-size limits, admission control and quotas.
- **External effects:** local outbox atomicity is not exactly-once external delivery. A real connector needs idempotency, destination binding, retry controls and reconciliation.
- **Persistence:** SQLite stores documents and outbox data in plaintext. Filesystem permissions, encryption, retention and backups are prerequisites for real data.

## Evaluation contract

The lab supplies scripted hostile tool calls, assuming an attacker already influenced the model. Success means that particular unauthorized operation did not execute. It does not measure prompt-injection detection, model resistance, or unknown-attack coverage. Production evaluation needs live attacker/defender runs in isolation, benign workloads and connector-specific bypass testing.
