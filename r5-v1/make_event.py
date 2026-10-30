"""Crea un evento SINTÉTICO nuevo para el ensayo elegido, sin llamar a Floodlight."""
import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from r5 import read_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = read_policy(json.loads(args.policy.read_text(encoding="utf-8")))
    if policy["source_mode"] != "synthetic":
        parser.error("Este generador solo admite políticas synthetic")
    event = {
        "schema_version": 1, "event_id": "synthetic-" + uuid.uuid4().hex,
        "trial_id": policy["trial_id"], "timestamp": datetime.now(timezone.utc).isoformat(),
        "sensor_id": policy["sensor_id"], "source_mode": "synthetic", "event_type": "alert",
        "direction": "request", "src_ip": policy["src_ip"], "dest_ip": policy["dest_ip"],
        "proto": policy["protocol"], "src_port": 45000, "dest_port": policy["dest_port"],
        "signature_id": policy["signature_ids"][0], "signature": "Marcador sintético R5_TEST_G2",
    }
    # La x impide sustituir una alerta o ensayo ya guardado.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(event, stream, indent=2, ensure_ascii=False)
    print(json.dumps({"status": "SYNTHETIC_EVENT_CREATED", "event_id": event["event_id"],
                      "path": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
