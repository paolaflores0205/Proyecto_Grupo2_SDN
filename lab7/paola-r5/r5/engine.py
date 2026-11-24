"""Une las piezas: linea de eve.json -> decision -> reglas en el borde -> incidente.

El acceso a Floodlight se inyecta como `backend` para poder probar el motor sin red.
Un backend debe ofrecer:
  existing_rule_names() -> set[str]
  install(rule: dict) -> None
  remove(name: str) -> None

Frenos contra el abuso (seccion "limits" de la politica): un tope de IPs bloqueadas a la vez,
un limite de bloqueos nuevos por minuto y un maximo de IPs por decision. Si un freno actua,
la IP no se bloquea, se conservan los bloqueos ya puestos y el incidente lo deja escrito.

No es seguro para varios hilos: el servicio lo usa detras de un candado.
"""
from __future__ import annotations

import copy
import math
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Deque, Dict, List, Optional, Protocol, Set

from .alerts import parse_ids_alert
from .block_state import BlockState, RecoveryError
from .decision import RepeatTracker, classify_alert
from .incidents import log_incident
from .intel import FeedReport, ThreatIntel
from .model import Action, Alert, Decision
from .policy import Policy
from .rules import RuleRejected, build_perimeter_rule, rule_names


class Backend(Protocol):
    def existing_rule_names(self) -> Set[str]: ...
    def install(self, rule: dict) -> None: ...
    def remove(self, name: str) -> None: ...


@dataclass
class Outcome:
    decision: Optional[Decision]
    installed: List[str] = field(default_factory=list)
    incident: Optional[dict] = None
    errors: List[str] = field(default_factory=list)
    rejected: Optional[str] = None  # stale | future; nunca modifica reglas ni reincidencias
    duplicate: bool = False
    throttled: List[str] = field(default_factory=list)  # IPs que un freno dejo sin bloquear


class Engine:
    def __init__(self, policy: Policy, intel: ThreatIntel, backend: Backend,
                 incident_path: Optional[str] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 dedupe_seconds: Optional[float] = None,
                 monotonic_clock: Callable[[], float] = time.monotonic,
                 state_path: Optional[str] = None):
        self.policy, self.intel, self.backend = policy, intel, backend
        self.incident_path, self.clock = incident_path, clock
        minimum_retention = policy.max_event_age_seconds + policy.max_future_skew_seconds
        if dedupe_seconds is None:
            dedupe_seconds = float(minimum_retention)
        if not math.isfinite(dedupe_seconds) or dedupe_seconds < minimum_retention:
            raise ValueError("dedupe_seconds debe cubrir la ventana de validez del evento")
        self.dedupe_seconds = dedupe_seconds
        self.monotonic_clock = monotonic_clock
        self.state_store = BlockState(state_path, policy)
        self.cleanup_errors: List[str] = []
        self.tracker = RepeatTracker(policy)
        self.feed_blocks: Set[str] = set()   # IPs bloqueadas por la lista negra (regla 2)
        self.blocks: Dict[str, dict] = {}    # IP -> motivo, reglas y vencimiento
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._recent_new: Deque[float] = deque()  # instantes de los bloqueos nuevos (ultimo minuto)
        self.last_brake: Optional[dict] = None
        self.stats = {"lines": 0, "invalid": 0, "duplicates": 0, "ignored": 0,
                      "incidents": 0, "blocks_installed": 0, "errors": 0, "throttled": 0,
                      "rejected_stale": 0, "rejected_future": 0, "last_rejection": None,
                      "last_event_at": None}

    # -- identidad exacta del evento; conservadora ante copias de espejos ---------
    def _is_duplicate(self, alert: Alert) -> bool:
        if alert.event_id is None:
            return False  # sin identidad suficiente no se descarta una alerta
        now = self.monotonic_clock()
        while self._seen and next(iter(self._seen.values())) < now - self.dedupe_seconds:
            self._seen.popitem(last=False)
        if alert.event_id in self._seen:
            return True  # repetir no renueva la retencion ni las reincidencias
        self._seen[alert.event_id] = now
        while len(self._seen) > 20000:
            self._seen.popitem(last=False)
        return False

    def process_line(self, line) -> Outcome:
        self.stats["lines"] += 1
        alert = parse_ids_alert(line)
        if alert is None:
            self.stats["invalid"] += 1
            return Outcome(decision=None)
        received_at = self.clock()
        age = (received_at - alert.timestamp).total_seconds()
        rejection = ("stale" if age > self.policy.max_event_age_seconds else
                     "future" if age < -self.policy.max_future_skew_seconds else None)
        if rejection:
            self.stats["rejected_" + rejection] += 1
            self.stats["last_rejection"] = {
                "reason": rejection, "event_at": alert.timestamp.isoformat(),
                "received_at": received_at.isoformat(), "age_seconds": age,
                "event_id": alert.event_id}
            return Outcome(decision=None, rejected=rejection)
        self.stats["last_event_at"] = alert.timestamp.isoformat()
        if self._is_duplicate(alert):
            self.stats["duplicates"] += 1
            return Outcome(decision=None, duplicate=True)
        decision = classify_alert(alert, self.intel, self.policy, self.tracker)
        if decision.action is Action.IGNORE:
            self.stats["ignored"] += 1
            return Outcome(decision=decision)
        decided_at = self.clock()
        outcome = Outcome(decision=decision)
        rules: List[dict] = []
        brakes: List[str] = []
        if decision.action is Action.BLOCK:
            self._prune(decided_at)
            try:
                existing = self.backend.existing_rule_names()
            except Exception as exc:
                outcome.errors.append(f"No se pudo consultar Floodlight: {exc}")
                existing = set()
            targets = list(decision.block_ips)
            limit = self.policy.max_ips_per_decision
            if len(targets) > limit:  # p. ej. una respuesta DNS con decenas de IPs
                outcome.throttled.extend(targets[limit:])
                brakes.append(f"maximo de {limit} IPs por decision ({len(targets)} pedidas)")
                targets = targets[:limit]
            pending = 0
            for ip in targets:
                current = self.blocks.get(ip)
                if current and datetime.fromisoformat(current["expires_at"]) <= decided_at:
                    outcome.errors.append(f"Limpieza pendiente para {ip}; no se renueva el bloqueo")
                    continue
                if not any(n in existing for n in rule_names(ip, self.policy).values()):
                    why = self._brake(pending)
                    if why:
                        outcome.throttled.append(ip)
                        brakes.append(why)
                        continue
                    pending += ip not in self.blocks
                    self._recent_new.append(decided_at.timestamp())
                try:
                    duration = decision.duration
                    if current:
                        duration = math.floor((datetime.fromisoformat(current["expires_at"]) - decided_at).total_seconds())
                        if duration < 1:
                            continue  # no se extiende el plazo al reparar una regla faltante
                    rules.extend(build_perimeter_rule(ip, self.policy, duration, existing))
                except RuleRejected as exc:
                    outcome.errors.append(str(exc))
            try:
                self._reserve_blocks(decision, rules, decided_at)
            except Exception as exc:
                outcome.errors.append(f"No se guardo el plazo; no se envian reglas: {exc}")
                rules = []
            for rule in rules:
                try:
                    self.backend.install(rule)
                except Exception as exc:  # Floodlight caido, tunel cortado, respuesta invalida
                    outcome.errors.append(f"No se instalo {rule['name']}: {exc}")
                    continue
                outcome.installed.append(rule["name"])
            if decision.policy_rule == 2:
                self.feed_blocks.update(decision.block_ips)
            try:
                self._register_blocks(decision, outcome.installed, decided_at)
            except Exception as exc:
                outcome.errors.append(f"No se actualizo el registro de estado: {exc}")
        installed_at = self.clock() if outcome.installed else None
        extra = {"errors": list(outcome.errors)}  # antes se agregaba despues de escribir el archivo
        if outcome.throttled:
            brake = "; ".join(dict.fromkeys(brakes))
            extra.update(brake=brake, throttled_ips=list(outcome.throttled),
                         blocked_ips=[ip for ip in decision.block_ips if ip not in outcome.throttled])
            self.last_brake = {"at": decided_at.isoformat(), "reason": brake, "ips": list(outcome.throttled)}
        outcome.incident = log_incident(alert, decision, rules, self.incident_path,
                                        decided_at=decided_at, installed_at=installed_at, extra=extra)
        self.stats["incidents"] += 1
        self.stats["blocks_installed"] += len(outcome.installed)
        self.stats["errors"] += len(outcome.errors)
        self.stats["throttled"] += len(outcome.throttled)
        return outcome

    # -- frenos ---------------------------------------------------------------------------
    def _save_blocks(self, blocks: Dict[str, dict]) -> None:
        self.state_store.save(blocks)
        self.blocks = blocks

    def _prune(self, now: datetime) -> None:
        """Limpia registros vencidos en Floodlight; conserva pendientes para reintentar."""
        self.cleanup_errors = []
        for ip in list(self.blocks):
            block = self.blocks[ip]
            if datetime.fromisoformat(block["expires_at"]) > now:
                continue
            failed = False
            for name in block["rules"]:
                try:
                    self.backend.remove(name)  # DELETE idempotente; incluye el registro del pusher
                except Exception as exc:
                    failed = True
                    self.cleanup_errors.append(f"No se retiro {name}: {exc}")
            candidate = copy.deepcopy(self.blocks)
            if failed:
                candidate[ip]["status"] = "cleanup_pending"
            else:
                del candidate[ip]
            try:
                self._save_blocks(candidate)
                if not failed:
                    self.feed_blocks.discard(ip)
            except Exception as exc:
                self.cleanup_errors.append(f"No se guardo la limpieza de {ip}: {exc}")
        while self._recent_new and self._recent_new[0] <= now.timestamp() - 60:
            self._recent_new.popleft()

    def maintenance(self) -> dict:
        self._prune(self.clock())
        return {"pending": sum(datetime.fromisoformat(b["expires_at"]) <= self.clock()
                               for b in self.blocks.values()),
                "errors": list(self.cleanup_errors)}

    def _brake(self, pending: int) -> Optional[str]:
        """Motivo por el que no se puede abrir un bloqueo nuevo, o None si se puede."""
        p = self.policy
        if len(self.blocks) + pending >= p.max_active_blocks:
            return f"tope de {p.max_active_blocks} IPs bloqueadas a la vez"
        if len(self._recent_new) >= p.max_new_blocks_per_minute:
            return f"limite de {p.max_new_blocks_per_minute} bloqueos nuevos por minuto"
        return None

    def brake_status(self) -> dict:
        """Estado de los frenos para /r5/health."""
        self._prune(self.clock())
        p = self.policy
        return {"active_blocks": len(self.blocks), "max_active_blocks": p.max_active_blocks,
                "new_blocks_last_minute": len(self._recent_new),
                "max_new_blocks_per_minute": p.max_new_blocks_per_minute,
                "engaged": (len(self.blocks) >= p.max_active_blocks
                            or len(self._recent_new) >= p.max_new_blocks_per_minute),
                "throttled_ips": self.stats["throttled"], "tracked_ips": self.tracker.tracked_ips(),
                "last": self.last_brake}

    # -- registro de bloqueos activos ----------------------------------------------------
    def _reserve_blocks(self, decision: Decision, rules: List[dict], now: datetime) -> None:
        # El plazo se guarda ANTES del primer POST: incluso una respuesta perdida
        # o un corte entre las dos reglas conserva una fecha original recuperable.
        if not rules:
            return
        candidate = copy.deepcopy(self.blocks)
        for ip in decision.block_ips:
            names = list(rule_names(ip, self.policy).values())
            if ip not in candidate and any(r["name"] in names for r in rules):
                candidate[ip] = {
                    "ip": ip, "reason": decision.reason, "policy_rule": decision.policy_rule,
                    "installed_at": now.isoformat(),
                    "expires_at": (now + timedelta(seconds=decision.duration)).isoformat(),
                    "rules": names, "status": "pending", "submitted_rules": []}
        self._save_blocks(candidate)

    def _register_blocks(self, decision: Decision, installed: List[str], now: datetime) -> None:
        if not installed:
            return
        candidate = copy.deepcopy(self.blocks)
        for ip in decision.block_ips:
            if ip not in candidate:
                continue
            block = candidate[ip]
            done = set(block.get("submitted_rules", [])) | (set(block["rules"]) & set(installed))
            block["submitted_rules"] = sorted(done)
            block["status"] = "submitted" if done == set(block["rules"]) else "partial"
        self._save_blocks(candidate)

    def recover_blocks(self, rules: Dict[str, dict]) -> List[str]:
        """Reconcilia con plazos persistidos; no estima duraciones ni reenvia reglas."""
        saved = self.state_store.load()
        prefix = self.policy.rule_prefix + "-"
        own = {n for n in rules if n.startswith(prefix)}
        known = {n for block in saved.values() for n in block["rules"]}
        unknown = own - known
        if unknown:
            raise RecoveryError("Reglas propias sin plazo verificable: " + ", ".join(sorted(unknown)))
        # Un registro sin ninguna regla en el pusher no provoca reinstalacion.
        retained = {ip: b for ip, b in saved.items() if set(b["rules"]) & own}
        self._save_blocks(retained)
        self.feed_blocks = {ip for ip, b in retained.items() if b["policy_rule"] == 2}
        self._prune(self.clock())
        return sorted(self.blocks)

    def active_blocks(self) -> List[dict]:
        self._prune(self.clock())
        return sorted(self.blocks.values(), key=lambda b: b["expires_at"])

    def unblock(self, ip: str) -> List[str]:
        """Desbloqueo manual: quita las reglas de la IP aunque el motor no las recuerde."""
        removed = []
        existing = self.backend.existing_rule_names()
        for name in rule_names(ip, self.policy).values():
            if name in existing:
                self.backend.remove(name)
                removed.append(name)
        candidate = copy.deepcopy(self.blocks)
        candidate.pop(ip, None)
        self._save_blocks(candidate)
        self.feed_blocks.discard(ip)
        return removed

    def reload_feed(self, feed) -> FeedReport:
        """Actualiza la lista negra y quita los bloqueos de las IPs que salieron del feed."""
        report = self.intel.update_blacklist(feed)
        existing = self.backend.existing_rule_names()
        for ip in sorted(self.feed_blocks):
            if self.intel.is_malicious_ip(ip):
                continue  # sigue en el feed (directamente o dentro de una red)
            for name in rule_names(ip, self.policy).values():
                if name in existing:
                    self.backend.remove(name)
            candidate = copy.deepcopy(self.blocks)
            candidate.pop(ip, None)
            self._save_blocks(candidate)
            self.feed_blocks.discard(ip)
        return report
