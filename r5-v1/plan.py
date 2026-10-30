"""Lee un evento normalizado y muestra el JSON propuesto, sin instalarlo."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from r5 import Rejected, build_rule, read_policy, validate_event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.example.json"))
    args = parser.parse_args()
    try:
        policy = read_policy(json.loads(args.policy.read_text(encoding="utf-8")))
        event = validate_event(json.loads(args.event.read_text(encoding="utf-8")), policy,
                               datetime.now(timezone.utc))
        print(json.dumps({"status": "PLANNED_NOT_SENT", "rule": build_rule(event, policy),
                          "traffic_block_verified": False}, indent=2))
    except (Rejected, ValueError, OSError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
