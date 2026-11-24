"""Registro de incidentes: una linea JSON por incidente, con sus marcas de tiempo."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Union

from .model import Action, Alert, Decision


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def log_incident(alert: Alert, decision: Decision, rules: Iterable[dict] = (),
                 path: Union[str, Path, None] = None, decided_at: Optional[datetime] = None,
                 installed_at: Optional[datetime] = None, extra: Optional[dict] = None) -> dict:
    """Arma el registro del incidente y, si hay `path`, lo agrega al archivo JSONL.

    Marcas de tiempo (para medir R5):
      event_at      hora del evento segun Suricata (deteccion)
      decided_at    hora en que el modulo decidio
      installed_at  hora en que Floodlight confirmo las reglas (si hubo bloqueo)
    `extra` agrega campos (errores, frenos) antes de escribir, para que queden en el archivo.
    """
    decided_at = decided_at or datetime.now(timezone.utc)
    names = [r.get("name") for r in rules]
    key = "|".join(str(x) for x in (alert.flow_id, alert.timestamp.isoformat(), alert.signature_id,
                                     alert.src_ip, alert.dest_ip, decision.action.value))
    record = {
        "incident_id": hashlib.sha256(key.encode()).hexdigest()[:16],
        "event_at": _iso(alert.timestamp),
        "decided_at": _iso(decided_at),
        "installed_at": _iso(installed_at),
        "detection_to_decision_ms": round((decided_at - alert.timestamp).total_seconds() * 1000, 1),
        "decision_to_install_ms": (round((installed_at - decided_at).total_seconds() * 1000, 1)
                                   if installed_at else None),
        "event_type": alert.event_type,
        "signature_id": alert.signature_id,
        "signature": alert.signature,
        "severity": alert.severity,
        "src_ip": alert.src_ip, "src_port": alert.src_port,
        "dest_ip": alert.dest_ip, "dest_port": alert.dest_port, "proto": alert.proto,
        "domain": alert.domain,
        "external_ip": decision.external_ip,
        "internal_host": decision.internal_host,
        "action": decision.action.value,
        "policy_rule": decision.policy_rule,
        "reason": decision.reason,
        "blocked_ips": list(decision.block_ips),
        "duration_s": decision.duration if decision.action is Action.BLOCK else 0,
        "rules": names,
    }
    record.update(extra or {})
    if path is not None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record
