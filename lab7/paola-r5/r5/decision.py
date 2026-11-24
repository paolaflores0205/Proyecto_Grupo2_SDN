"""R5-02: politica de decision (que alerta produce que accion).

Las reglas se evaluan en orden; la primera que coincide decide:
  1. IP externa en lista blanca           -> LOG
  2. Origen o destino en lista negra      -> BLOCK (feed_seconds)
  3. Dominio malicioso (DNS / SNI / Host) -> BLOCK de las IPs resueltas
  4. Alerta de severidad 1                -> BLOCK (con escalada si reincide)
  5. Alerta de severidad 2                -> WATCH; BLOCK si llega al umbral en la ventana
  6. Alerta de severidad 3 o desconocida  -> LOG
Eventos dns/tls/http sin indicadores -> IGNORE. Trafico solo interno -> LOG (es R3, no R5).
"""
from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime
from typing import Deque, List, Optional

from .intel import ThreatIntel
from .model import Action, Alert, Decision
from .policy import Policy


class RepeatTracker:
    """Memoria de alertas por IP externa, medida con la hora de los eventos (no del reloj).

    Tiene tamano maximo (policy.max_tracked_ips): con IPs falsificadas sin fin, un atacante
    podria agotar la RAM de la VM app. Al llenarse se olvida la IP menos reciente.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self._watch: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._blocks: "OrderedDict[str, Deque[float]]" = OrderedDict()

    def _queue(self, table: "OrderedDict[str, Deque[float]]", ip: str) -> Deque[float]:
        q = table.get(ip)
        if q is None:
            q = table[ip] = deque()
        table.move_to_end(ip)
        while len(table) > self.policy.max_tracked_ips:
            table.popitem(last=False)
        return q

    def tracked_ips(self) -> int:
        return len(set(self._watch) | set(self._blocks))

    def watch_count(self, ip: str, when: datetime) -> int:
        """Registra una alerta media y devuelve cuantas hay en la ventana."""
        t = when.timestamp()
        q = self._queue(self._watch, ip)
        q.append(t)
        latest = max(q)
        while q and q[0] < latest - self.policy.watch_window_seconds:
            q.popleft()
        return sum(1 for x in q if x >= latest - self.policy.watch_window_seconds)

    def reset_watch(self, ip: str) -> None:
        self._watch.pop(ip, None)

    def block_duration(self, ip: str, when: datetime) -> int:
        """Duracion del siguiente bloqueo: base x factor^(reincidencias), con tope."""
        t = when.timestamp()
        q = self._queue(self._blocks, ip)
        while q and q[0] < t - self.policy.repeat_memory_seconds:
            q.popleft()
        previous = len(q)
        q.append(t)
        p = self.policy
        return min(p.base_seconds * (p.escalation_factor ** previous), p.max_seconds)


def _external(alert: Alert, policy: Policy) -> Optional[str]:
    """El extremo externo del evento (el que se podria bloquear en el borde)."""
    candidates: List[str] = [ip for ip in (alert.src_ip, alert.dest_ip) if not policy.is_internal(ip)]
    return candidates[0] if candidates else None


def _internal(alert: Alert, policy: Policy) -> Optional[str]:
    for ip in (alert.src_ip, alert.dest_ip):
        if policy.is_internal(ip):
            return ip
    return None


def classify_alert(alert: Alert, intel: ThreatIntel, policy: Policy,
                   tracker: Optional[RepeatTracker] = None) -> Decision:
    """Decide la accion para un evento ya parseado. No instala nada."""
    tracker = tracker or RepeatTracker(policy)
    ext = _external(alert, policy)
    host = _internal(alert, policy)

    if ext is None:
        return Decision(Action.LOG, "Trafico interno: fuera del alcance de R5 (lo cubre R3)", 0,
                        internal_host=host)
    domain_hit = bool(alert.domain) and intel.is_malicious_domain(alert.domain)
    # En una respuesta DNS el extremo externo es el resolvedor (suele estar en la lista
    # blanca); lo que se bloquea son las IPs resueltas, asi que se evalua el dominio.
    if intel.is_whitelisted(ext) and not (domain_hit and alert.event_type == "dns"):  # regla 1
        return Decision(Action.LOG, f"{ext} esta en la lista blanca: nunca se bloquea", 1,
                        internal_host=host, external_ip=ext)
    if intel.is_malicious_ip(ext):  # regla 2
        return Decision(Action.BLOCK, f"{ext} esta en la lista negra", 2, block_ips=(ext,),
                        duration=policy.feed_seconds, internal_host=host, external_ip=ext)
    if domain_hit:  # regla 3
        ips = [ip for ip in alert.resolved_ips
               if not policy.is_internal(ip) and not intel.is_whitelisted(ip)]
        if (alert.event_type in ("tls", "http", "alert") and ext not in ips
                and not intel.is_whitelisted(ext)):
            ips.append(ext)  # en TLS/HTTP el extremo externo ya es el servidor malicioso
        if not ips:
            return Decision(Action.LOG, f"Dominio malicioso {alert.domain} sin IP externa que bloquear", 3,
                            internal_host=host, external_ip=ext)
        return Decision(Action.BLOCK, f"Consulta a dominio malicioso {alert.domain}", 3,
                        block_ips=tuple(ips), duration=policy.base_seconds,
                        internal_host=host, external_ip=ext)
    if alert.event_type != "alert":
        return Decision(Action.IGNORE, "Evento sin indicadores de amenaza", 0,
                        internal_host=host, external_ip=ext)

    severity = policy.effective_severity(alert.signature_id, alert.severity)
    if severity == 1:  # regla 4
        duration = tracker.block_duration(ext, alert.timestamp)
        return Decision(Action.BLOCK, f"Alerta de severidad 1: {alert.signature}", 4,
                        block_ips=(ext,), duration=duration, internal_host=host, external_ip=ext)
    if severity == 2:  # regla 5
        count = tracker.watch_count(ext, alert.timestamp)
        if count >= policy.watch_threshold:
            tracker.reset_watch(ext)
            duration = tracker.block_duration(ext, alert.timestamp)
            return Decision(Action.BLOCK,
                            f"{count} alertas de severidad 2 en {policy.watch_window_seconds} s", 5,
                            block_ips=(ext,), duration=duration, internal_host=host, external_ip=ext)
        return Decision(Action.WATCH,
                        f"Severidad 2: {count} de {policy.watch_threshold} alertas en la ventana", 5,
                        internal_host=host, external_ip=ext)
    label = "desconocida" if severity is None else str(severity)
    return Decision(Action.LOG, f"Alerta de severidad {label}: solo se registra", 6,
                    internal_host=host, external_ip=ext)
