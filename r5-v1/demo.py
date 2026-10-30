"""Demo local. No se conecta a Floodlight, SSH ni Suricata."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from r5 import Mitigator, SimulatedSwitch, build_rule, read_policy, validate_event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.example.json"))
    parser.add_argument("--output", type=Path, required=True, help="Carpeta local nueva para evidencia simulada")
    args = parser.parse_args()
    policy = read_policy(json.loads(args.policy.read_text(encoding="utf-8")))
    # No sobrescribir evidencia de un ensayo anterior.
    args.output.mkdir(parents=True, exist_ok=False)
    event = {
        "schema_version": 1, "event_id": "synthetic-alert-001",
        "trial_id": policy["trial_id"], "sensor_id": policy["sensor_id"],
        "source_mode": "synthetic", "direction": "request",
        "timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
        "src_ip": policy["src_ip"], "dest_ip": policy["dest_ip"],
        "proto": policy["protocol"], "src_port": 45000, "dest_port": policy["dest_port"],
        "signature_id": policy["signature_ids"][0], "signature": "Marcador sintético R5_TEST_G2",
    }
    clock = [0.0]
    switch = SimulatedSwitch(lambda: clock[0])
    engine = Mitigator(args.output / "audit.sqlite3", policy, switch)
    try:
        accepted = engine.process(event)
        duplicate = engine.process(event)
        invalid = engine.process(dict(event, event_id="synthetic-invalid-002", dest_ip="192.0.2.99"))
        retired = engine.retire(event["event_id"])
        duplicate_after_retirement = engine.process(event)
        expiry_event = dict(event, event_id="synthetic-expiry-003")
        expiry_install = engine.process(expiry_event)
        clock[0] = policy["duration_seconds"] + 1
        expiry = {
            "status": "SIMULATED_EXPIRY_OBSERVED",
            "rule_absent": switch.observe(expiry_install["rule"]["name"]) is None,
            "simulation": True, "service_recovery_verified": False,
        }
        report = {
            "scope": "SOLO SIMULACIÓN LOCAL; no demuestra detección IDS ni bloqueo real",
            "accepted": accepted, "duplicate": duplicate, "invalid": invalid,
            "retired": retired, "duplicate_after_retirement": duplicate_after_retirement,
            "expiry": expiry, "simulated_install_calls": switch.install_calls,
        }
        # Generar el JSON propuesto para Floodlight; no enviarlo.
        plan = build_rule(validate_event(event, policy, datetime.now(timezone.utc)), policy)
        for filename, value in (("event.synthetic.json", event), ("policy.json", policy),
                                ("rule.proposed.json", plan), ("results.simulated.json", report)):
            (args.output / filename).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))
    finally:
        engine.close()


if __name__ == "__main__":
    main()
