"""Operaciones R5 explícitas en el controller. La acción check solo hace GET."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from floodlight import FloodlightSwitch, IntegrationError
from r5 import Mitigator, Rejected, build_rule, read_policy, validate_event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "apply", "retire"])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--event", type=Path, help="Evento normalizado para check/apply")
    parser.add_argument("--event-id", help="ID ya registrado, para retire")
    parser.add_argument("--database", type=Path, help="SQLite independiente de R1/R2")
    parser.add_argument("--confirm-controlled-test", action="store_true",
                        help="Habilita la escritura de la regla del ensayo acordado")
    args = parser.parse_args()
    try:
        writes = args.action != "check"
        if writes and not args.confirm_controlled_test:
            raise Rejected("Falta habilitación explícita para aplicar o retirar")
        if writes and args.database is None:
            raise Rejected("Se requiere --database para conservar trazabilidad")
        if args.action == "retire" and (not args.event_id or not args.database.is_file()):
            raise Rejected("Retiro requiere event-id y la bitácora existente")
        policy = read_policy(json.loads(args.policy.read_text(encoding="utf-8")))
        if policy["dest_port"] in {22, 3306, 33060, 6642, 6653, 8080}:
            raise Rejected("No se admiten servicios de gestión/control como destino del ensayo")
        # Aún no hay receptor autenticado: esta CLI solo admite ensayos sintéticos/reproducidos.
        if policy["source_mode"] == "live":
            raise Rejected("Recepción de alertas en vivo aún no habilitada")
        backend = FloodlightSwitch(policy["switch_dpid"], enable_writes=writes)
        if args.action == "retire":
            engine = Mitigator(args.database, policy, backend)
            try:
                result = engine.retire(args.event_id)
            finally:
                engine.close()
        else:
            if args.event is None:
                raise Rejected("Se requiere --event")
            raw = json.loads(args.event.read_text(encoding="utf-8"))
            if args.action == "check":
                event = validate_event(raw, policy, datetime.now(timezone.utc))
                rule = build_rule(event, policy)
                result = {"status": "PREFLIGHT_READ_ONLY", "rule": rule,
                          "checks": backend.preflight(rule), "traffic_block_verified": False}
            else:
                engine = Mitigator(args.database, policy, backend)
                try:
                    result = engine.process(raw)
                finally:
                    engine.close()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["status"] in {"PREFLIGHT_READ_ONLY", "RULE_VERIFIED_TRAFFIC_PENDING",
                                          "RULE_RETIRED_RECOVERY_PENDING", "DUPLICATE"} else 2
    except (Rejected, IntegrationError, ValueError, OSError) as exc:
        print(json.dumps({"status": "STOPPED", "reason": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
