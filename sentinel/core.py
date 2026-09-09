"""Bounded, evidence-based investigations. Input is data, never executable code."""
from collections import defaultdict
from datetime import datetime, timedelta

MAX_EVENTS = 10000
READ_TOOLS = frozenset({'query_events', 'get_asset'})


def authorize(tool: str) -> bool:
    """Fail closed. This prototype has no production mutation capabilities."""
    return tool in READ_TOOLS


def investigate(events: list, tenant: str) -> dict:
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError('A tenant scope is required')
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError('Expected at most 10000 events')
    scoped, seen = [], set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError('Each event must be an object')
        if event.get('tenant') != tenant:
            continue
        for field in ('id', 'actor', 'type', 'timestamp'):
            if not isinstance(event.get(field), str) or not event[field].strip():
                raise ValueError(f'Missing or invalid {field}')
        if event['id'] in seen:
            raise ValueError('Duplicate event ID')
        seen.add(event['id'])
        timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        if timestamp.utcoffset() is None:
            raise ValueError('Timestamps must include a timezone')
        scoped.append((timestamp, event))
    scoped.sort(key=lambda item: item[0])
    findings, failures = [], defaultdict(list)

    def add(rule, severity, title, evidence, recommendation):
        findings.append(dict(id=f'finding-{len(findings)+1}', rule=rule,
                             severity=severity, title=title,
                             evidence_ids=evidence, recommendation=recommendation,
                             status='needs_analyst_review'))

    for timestamp, event in scoped:
        actor, kind = event['actor'], event['type']
        if kind == 'login_failed':
            failures[actor].append((timestamp, event['id']))
        elif kind == 'login_success':
            recent = [eid for ts, eid in failures[actor]
                      if timedelta(0) <= timestamp-ts <= timedelta(minutes=10)]
            if len(recent) >= 5:
                add('AUTH-001', 'high', 'Successful login after repeated failures',
                    recent + [event['id']],
                    'Verify the login with the account owner and inspect session activity.')
        elif kind == 'privilege_granted' and event.get('role') == 'admin':
            add('IAM-001', 'medium', 'Administrative access granted', [event['id']],
                'Check the approved change record and the granting identity.')
        elif kind == 'agent_tool_call':
            tool = event.get('tool')
            if not isinstance(tool, str) or not authorize(tool):
                add('AGENT-001', 'high', 'Agent requested a tool outside the local allowlist',
                    [event['id']], 'Inspect the agent session and its tool gateway logs.')
        elif kind == 'retrieved_content':
            content = event.get('content', '')
            if not isinstance(content, str):
                raise ValueError('Content must be text')
            if any(marker in content.lower() for marker in
                   ('ignore previous instructions', 'reveal your secrets', 'disable audit')):
                add('AGENT-002', 'medium', 'Possible malicious instructions in retrieved content',
                    [event['id']],
                    'Inspect the source. Phrase matching is a weak signal, not proof of an attack.')
    return dict(tenant=tenant, events_examined=len(scoped), findings=findings,
                mode='offline_read_only', actions_executed=[],
                limitations=['Rule-based prototype; no live model or production connectors.',
                             'Tenant selection is filtering, not authentication.',
                             'Findings are leads, not verified compromises.'])
