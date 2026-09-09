import argparse
import json
from pathlib import Path
from .core import investigate


def main():
    parser = argparse.ArgumentParser(description='Investigate a local JSON event export')
    parser.add_argument('events', type=Path)
    parser.add_argument('--tenant', required=True)
    args = parser.parse_args()
    try:
        with args.events.open('rb') as stream:
            raw = stream.read(5_000_001)
        if len(raw) > 5_000_000:
            raise ValueError('Input exceeds 5 MB')
        report = investigate(json.loads(raw), args.tenant)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Invalid input: {exc}\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
