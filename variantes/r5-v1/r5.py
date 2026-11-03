"""Mitigación R5: validación, planificación y ensayo local sin acceso a red.

Este módulo no importa R1/R2 ni ejecuta comandos del sistema o peticiones HTTP.
El adaptador real se encuentra en floodlight.py y requiere habilitación explícita.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


class Rejected(ValueError):
    """Entrada rechazada antes de solicitar una regla."""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def integer(value: object, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Rejected(f"{label}: se requiere entero entre {low} y {high}")
    return value


def identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", value):
        raise Rejected(f"{label}: identificador inválido")
    return value


def ipv4(value: object) -> str:
    if not isinstance(value, str):
        raise Rejected("La dirección IPv4 debe ser texto")
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError, ValueError):
        raise Rejected("Se requiere una dirección IPv4 individual válida") from None
    if addr.is_multicast or addr.is_unspecified or int(addr) == 0xFFFFFFFF:
        raise Rejected("Dirección no admitida como extremo del ensayo")
    return str(addr)


def timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise Rejected("timestamp debe ser texto ISO 8601 con zona horaria")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Rejected("timestamp inválido") from None
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise Rejected("timestamp debe incluir zona horaria")
    return dt.astimezone(timezone.utc)


def read_policy(raw: dict) -> dict:
    """La política local fija el switch, alcance, prioridad y vigencia."""
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        raise Rejected("Política de versión no soportada")
    p = dict(raw)
    for key in ("policy_id", "trial_id", "sensor_id"):
        identifier(p.get(key), key)
    if p.get("source_mode") not in {"synthetic", "replayed", "live"}:
        raise Rejected("source_mode debe ser synthetic, replayed o live")
    if p.get("direction") != "request":
        raise Rejected("Esta versión solo admite alertas del sentido de solicitud")
    if p.get("protocol") not in {"TCP", "UDP"}:
        raise Rejected("Esta versión solo admite TCP y UDP")
    p["src_ip"], p["dest_ip"] = ipv4(p.get("src_ip")), ipv4(p.get("dest_ip"))
    if p["src_ip"] == p["dest_ip"]:
        raise Rejected("Origen y destino deben ser distintos")
    integer(p.get("dest_port"), "dest_port", 1, 65535)
    integer(p.get("ingress_port"), "ingress_port", 1, 65279)
    integer(p.get("priority"), "priority", 1, 65535)
    integer(p.get("duration_seconds"), "duration_seconds", 1, 300)
    integer(p.get("max_event_age_seconds"), "max_event_age_seconds", 1, 3600)
    integer(p.get("future_tolerance_seconds"), "future_tolerance_seconds", 0, 60)
    if not isinstance(p.get("switch_dpid"), str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}", p["switch_dpid"]
    ):
        raise Rejected("switch_dpid inválido")
    p["switch_dpid"] = p["switch_dpid"].lower()
    signatures = p.get("signature_ids")
    if not isinstance(signatures, list) or not signatures:
        raise Rejected("La política debe enumerar firmas autorizadas")
    for sid in signatures:
        integer(sid, "signature_id", 1, 2**32 - 1)
    p["protected_ips"] = [ipv4(x) for x in p.get("protected_ips", [])]
    if p["src_ip"] in p["protected_ips"] or p["dest_ip"] in p["protected_ips"]:
        raise Rejected("El alcance coincide con una dirección protegida")
    return p


def validate_event(raw: dict, policy: dict, now: datetime) -> dict:
    """No acepta reglas ni parámetros de switch enviados por el emisor."""
    fields = {
        "schema_version", "event_id", "trial_id", "timestamp", "sensor_id",
        "source_mode", "event_type", "direction", "src_ip", "dest_ip",
        "proto", "src_port", "dest_port", "signature_id", "signature",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise Rejected("Campos ausentes o inesperados en el evento normalizado")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise Rejected("Versión de evento no soportada")
    event = dict(raw)
    identifier(event["event_id"], "event_id")
    for field in ("trial_id", "sensor_id", "source_mode", "direction"):
        if event[field] != policy[field]:
            raise Rejected(f"{field} no corresponde a la política del ensayo")
    if event["event_type"] != "alert" or event["proto"] != policy["protocol"]:
        raise Rejected("Tipo de evento o protocolo no autorizado")
    for field in ("src_ip", "dest_ip"):
        event[field] = ipv4(event[field])
        if event[field] != policy[field]:
            raise Rejected(f"{field} fuera del alcance autorizado")
    integer(event["src_port"], "src_port", 1, 65535)
    integer(event["dest_port"], "dest_port", 1, 65535)
    if event["dest_port"] != policy["dest_port"]:
        raise Rejected("Servicio fuera del alcance autorizado")
    integer(event["signature_id"], "signature_id", 1, 2**32 - 1)
    if event["signature_id"] not in policy["signature_ids"]:
        raise Rejected("La firma no autoriza mitigación automática")
    if not isinstance(event["signature"], str) or not 1 <= len(event["signature"]) <= 256:
        raise Rejected("Descripción de firma inválida")
    dt = timestamp(event["timestamp"])
    age = (now.astimezone(timezone.utc) - dt).total_seconds()
    if age > policy["max_event_age_seconds"]:
        raise Rejected("Evento antiguo; requiere nueva evaluación")
    if age < -policy["future_tolerance_seconds"]:
        raise Rejected("Evento fechado en el futuro")
    event["timestamp"] = dt.isoformat()
    return event


def build_rule(event: dict, policy: dict) -> dict:
    """Drop de un servicio en un sentido. No instala la regla."""
    key = canonical([policy["policy_id"], event["trial_id"], event["event_id"]])
    suffix = hashlib.sha256(key.encode()).hexdigest()[:24]
    transport = "tcp" if event["proto"] == "TCP" else "udp"
    return {
        "switch": policy["switch_dpid"], "name": "g2-r5-adrian-" + suffix,
        "table": "0", "priority": str(policy["priority"]), "active": "true",
        "idle_timeout": "0", "hard_timeout": str(policy["duration_seconds"]),
        "in_port": str(policy["ingress_port"]), "eth_type": "0x0800",
        "ip_proto": "6" if transport == "tcp" else "17",
        "ipv4_src": event["src_ip"] + "/32", "ipv4_dst": event["dest_ip"] + "/32",
        transport + "_dst": str(event["dest_port"]), "actions": "",
    }


class SimulatedSwitch:
    """Doble de prueba local; no representa un switch o tráfico reales."""
    simulation = True
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.rules: dict[str, tuple[dict, float]] = {}
        self.install_calls = 0
        self.remove_calls = 0

    def install(self, rule: dict) -> None:
        self.install_calls += 1
        self.rules[rule["name"]] = (dict(rule), self.clock() + int(rule["hard_timeout"]))

    def observe(self, name: str) -> dict | None:
        item = self.rules.get(name)
        if item is None:
            return None
        if self.clock() >= item[1]:
            del self.rules[name]
            return None
        return dict(item[0])

    def remove(self, name: str) -> None:
        self.remove_calls += 1
        self.rules.pop(name, None)


class Mitigator:
    """Registro durable. Regla observada y bloqueo de tráfico son hitos distintos."""
    def __init__(self, database: str | Path, policy: dict, backend):
        if type(getattr(backend, "simulation", None)) is not bool:
            raise TypeError("El backend debe identificar explícitamente si es simulado")
        self.simulation = backend.simulation
        self.policy = read_policy(policy)
        self.backend = backend
        self.conn = sqlite3.connect(str(database), isolation_level=None)
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                event_json TEXT NOT NULL,
                rule_json TEXT NOT NULL, policy_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, recorded_at TEXT NOT NULL,
                event_key TEXT, result_json TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self.conn.close()

    def _record(self, key: str | None, result: dict) -> None:
        self.conn.execute("INSERT INTO audit(recorded_at,event_key,result_json) VALUES(?,?,?)",
                          (datetime.now(timezone.utc).isoformat(), key, canonical(result)))
        if key is not None:
            self.conn.execute("UPDATE events SET result_json=? WHERE event_key=?",
                              (canonical(result), key))

    def process(self, raw: dict, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        start = time.perf_counter()
        try:
            event = validate_event(raw, self.policy, now)
        except Rejected as exc:
            result = {"status": "REJECTED", "reason": str(exc), "simulation": self.simulation}
            self._record(None, result)
            return result
        key = canonical(["simulated" if self.simulation else "floodlight",
                         event["sensor_id"], event["trial_id"], event["event_id"]])
        fingerprint = hashlib.sha256(canonical(event).encode()).hexdigest()
        rule = build_rule(event, self.policy)
        result = {
            "status": "INSTALL_REQUESTED", "simulation": self.simulation,
            "source_mode": event["source_mode"], "event_id": event["event_id"],
            "trial_id": event["trial_id"], "policy_id": self.policy["policy_id"],
            "received_at": now.isoformat(), "rule": rule,
            "traffic_block_verified": False, "service_recovery_verified": False,
        }
        # Reservar antes de instalar: un reintento no reinstala ni renueva el TTL.
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            prior = self.conn.execute(
                "SELECT fingerprint,result_json FROM events WHERE event_key=?", (key,)
            ).fetchone()
            if prior:
                self.conn.execute("COMMIT")
                result = {
                    "status": "DUPLICATE" if prior[0] == fingerprint else "REJECTED",
                    "reason": "Evento ya registrado" if prior[0] == fingerprint else "ID reutilizado con otro contenido",
                    "simulation": self.simulation, "event_id": event["event_id"],
                    "previous_result": json.loads(prior[1]),
                }
                self._record(None, result)
                return result
            self.conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?)",
                              (key, fingerprint, canonical(raw), canonical(rule), canonical(self.policy), canonical(result)))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        self._record(key, result)
        try:
            self.backend.install(rule)
        except Exception as exc:
            # No se presume ausencia: el fallo podría ocurrir después de aplicar.
            result.update(status="INSTALL_UNCONFIRMED", error_type=type(exc).__name__)
        else:
            try:
                observed = self.backend.observe(rule["name"])
                verified = "SIMULATED_RULE_VERIFIED" if self.simulation else "RULE_VERIFIED_TRAFFIC_PENDING"
                result.update(status=verified if observed == rule else "VERIFICATION_FAILED")
            except Exception as exc:
                result.update(status="VERIFICATION_FAILED", error_type=type(exc).__name__)
        result["local_processing_ms"] = round((time.perf_counter() - start) * 1000, 3)
        result["measurement_scope"] = (
            "Procesamiento local simulado; no latencia IDS ni bloqueo de tráfico" if self.simulation
            else "Recepción local hasta resultado de regla; bloqueo efectivo todavía no medido")
        self._record(key, result)
        return result

    def retire(self, event_id: str) -> dict:
        identifier(event_id, "event_id")
        key = canonical(["simulated" if self.simulation else "floodlight",
                         self.policy["sensor_id"], self.policy["trial_id"], event_id])
        row = self.conn.execute("SELECT rule_json,result_json FROM events WHERE event_key=?", (key,)).fetchone()
        if row is None:
            raise Rejected("Evento no registrado: no se puede retirar una regla ajena")
        rule, result = json.loads(row[0]), json.loads(row[1])
        if not rule["name"].startswith("g2-r5-adrian-") or rule["switch"] != self.policy["switch_dpid"]:
            raise Rejected("La regla registrada no corresponde al alcance actual")
        try:
            if hasattr(self.backend, "track"):
                self.backend.track(rule)
            observed = self.backend.observe(rule["name"])
            if observed is not None and observed != rule:
                result.update(status="REMOVAL_UNCONFIRMED", reason="La entrada observada cambió; no se elimina")
            else:
                # Retirar también la definición persistida cuando la entrada ya expiró.
                self.backend.remove(rule["name"])
                retired = "SIMULATED_RULE_RETIRED" if self.simulation else "RULE_RETIRED_RECOVERY_PENDING"
                result["status"] = retired if self.backend.observe(rule["name"]) is None else "REMOVAL_UNCONFIRMED"
        except Exception as exc:
            result.update(status="REMOVAL_UNCONFIRMED", error_type=type(exc).__name__)
        result["service_recovery_verified"] = False
        self._record(key, result)
        return result


def normalize_eve(eve: dict, *, event_id: str, trial_id: str,
                  sensor_id: str, source_mode: str, direction: str) -> dict:
    """Propuesta de envoltorio; conservar el EVE original en evidencia aparte.

    El colector aporta ID estable y contexto de ensayo, no se inventan puertos.
    La autenticación del sensor y el transporte son integración pendiente.
    """
    if not isinstance(eve, dict) or eve.get("event_type") != "alert":
        raise Rejected("El EVE no es una alerta")
    alert = eve.get("alert")
    if not isinstance(alert, dict):
        raise Rejected("Falta el objeto alert del EVE")
    return {
        "schema_version": 1, "event_id": event_id, "trial_id": trial_id,
        "sensor_id": sensor_id, "source_mode": source_mode, "direction": direction,
        "timestamp": eve.get("timestamp"), "event_type": "alert",
        "src_ip": eve.get("src_ip"), "dest_ip": eve.get("dest_ip"),
        "proto": eve.get("proto"), "src_port": eve.get("src_port"),
        "dest_port": eve.get("dest_port"), "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
    }
