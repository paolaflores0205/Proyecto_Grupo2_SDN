"""Carga y validacion del archivo de politica de R5."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_DPID = re.compile(r"(?:[0-9a-f]{2}:){7}[0-9a-f]{2}")
_PREFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")


class PolicyError(ValueError):
    """La politica no es valida; el modulo no debe arrancar con ella."""


@dataclass(frozen=True)
class Policy:
    edge_dpid: str
    edge_port: int
    rule_prefix: str
    priority: int
    base_seconds: int
    max_seconds: int
    escalation_factor: int
    feed_seconds: int
    repeat_memory_seconds: int
    watch_window_seconds: int
    watch_threshold: int
    internal_networks: Tuple[Network, ...]
    whitelist: Tuple[Network, ...]
    blacklist_file: Optional[str] = None
    incident_log: Optional[str] = None
    # Calibracion por linea base: firma (sid) -> severidad efectiva (1, 2 o 3).
    severity_overrides: Tuple[Tuple[int, int], ...] = ()
    # Frenos contra el abuso del propio R5 (seccion "limits", opcional). Un atacante que
    # falsifica IPs o envenena el feed no debe poder llenar el switch ni la memoria.
    max_active_blocks: int = 500          # IPs bloqueadas a la vez (500 = lo medido en sw5)
    max_new_blocks_per_minute: int = 30   # bloqueos nuevos por minuto
    max_ips_per_decision: int = 8         # IPs que puede bloquear una sola respuesta DNS
    max_tracked_ips: int = 50000          # IPs que recuerda el contador de reincidencias
    feed_min_prefix_v4: int = 16          # el feed no puede traer redes mas amplias que /16
    feed_min_prefix_v6: int = 32
    max_event_age_seconds: int = 120
    max_future_skew_seconds: int = 5

    def effective_severity(self, sid: Optional[int], severity: Optional[int]) -> Optional[int]:
        for s, sev in self.severity_overrides:
            if s == sid:
                return sev
        return severity

    def is_internal(self, ip: str) -> bool:
        addr = _addr(ip)
        return addr is not None and any(addr in net for net in self.internal_networks)

    def is_whitelisted(self, ip: str) -> bool:
        addr = _addr(ip)
        return addr is not None and any(addr in net for net in self.whitelist)


def _addr(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None


def _int(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise PolicyError(f"{name} debe ser un entero entre {low} y {high}")
    return value


def _networks(values: Any, name: str) -> Tuple[Network, ...]:
    if not isinstance(values, list):
        raise PolicyError(f"{name} debe ser una lista")
    nets = []
    for item in values:
        try:
            nets.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError as exc:
            raise PolicyError(f"{name}: entrada invalida {item!r}") from exc
    return tuple(nets)


def _overrides(values: Any) -> Tuple[Tuple[int, int], ...]:
    """{"2013031": {"severity": 3, "motivo": "..."}} o {"2013031": 3} -> ((2013031, 3),)"""
    if not isinstance(values, dict):
        raise PolicyError("severity_overrides debe ser un objeto sid -> severidad")
    out = []
    for sid, value in values.items():
        sev = value.get("severity") if isinstance(value, dict) else value
        try:
            sid_int = int(sid)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"severity_overrides: sid invalido {sid!r}") from exc
        out.append((_int(sid_int, "severity_overrides.sid", 1, 2 ** 32 - 1),
                    _int(sev, f"severity_overrides[{sid}]", 1, 3)))
    return tuple(out)


def load_policy(source: Union[str, Path, Mapping[str, Any]]) -> Policy:
    """Lee la politica desde un archivo JSON o un dict y la valida completa."""
    if isinstance(source, Mapping):
        raw = dict(source)
    else:
        try:
            raw = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"No se pudo leer la politica: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise PolicyError("Version de politica no soportada")
    edge = raw.get("edge") or {}
    dpid = str(edge.get("switch_dpid", "")).lower()
    if not _DPID.fullmatch(dpid):
        raise PolicyError("edge.switch_dpid invalido")
    prefix = raw.get("rule_prefix")
    if not isinstance(prefix, str) or not _PREFIX.fullmatch(prefix):
        raise PolicyError("rule_prefix invalido")
    d = raw.get("durations") or {}
    w = raw.get("watch") or {}
    lim = raw.get("limits", {})
    if not isinstance(lim, dict):
        raise PolicyError("limits debe ser un objeto")
    events = raw.get("events", {})
    if not isinstance(events, dict):
        raise PolicyError("events debe ser un objeto")
    policy = Policy(
        max_event_age_seconds=_int(events.get("max_age_seconds", 120),
                                   "events.max_age_seconds", 1, 3600),
        max_future_skew_seconds=_int(events.get("max_future_skew_seconds", 5),
                                     "events.max_future_skew_seconds", 0, 60),
        edge_dpid=dpid,
        edge_port=_int(edge.get("port"), "edge.port", 1, 65279),
        rule_prefix=prefix,
        priority=_int(raw.get("priority"), "priority", 1, 65535),
        base_seconds=_int(d.get("base_seconds"), "durations.base_seconds", 1, 65535),
        max_seconds=_int(d.get("max_seconds"), "durations.max_seconds", 1, 65535),
        escalation_factor=_int(d.get("escalation_factor"), "durations.escalation_factor", 1, 10),
        feed_seconds=_int(d.get("feed_seconds"), "durations.feed_seconds", 1, 65535),
        repeat_memory_seconds=_int(d.get("repeat_memory_seconds", 86400),
                                   "durations.repeat_memory_seconds", 1, 7 * 86400),
        watch_window_seconds=_int(w.get("window_seconds"), "watch.window_seconds", 1, 3600),
        watch_threshold=_int(w.get("threshold"), "watch.threshold", 1, 1000),
        internal_networks=_networks(raw.get("internal_networks"), "internal_networks"),
        whitelist=_networks(raw.get("whitelist"), "whitelist"),
        blacklist_file=raw.get("blacklist_file"),
        incident_log=raw.get("incident_log"),
        severity_overrides=_overrides(raw.get("severity_overrides", {})),
        max_active_blocks=_int(lim.get("max_active_blocks", 500), "limits.max_active_blocks", 1, 10000),
        max_new_blocks_per_minute=_int(lim.get("max_new_blocks_per_minute", 30),
                                       "limits.max_new_blocks_per_minute", 1, 10000),
        max_ips_per_decision=_int(lim.get("max_ips_per_decision", 8), "limits.max_ips_per_decision", 1, 64),
        max_tracked_ips=_int(lim.get("max_tracked_ips", 50000), "limits.max_tracked_ips", 100, 1000000),
        feed_min_prefix_v4=_int(lim.get("feed_min_prefix_v4", 16), "limits.feed_min_prefix_v4", 0, 32),
        feed_min_prefix_v6=_int(lim.get("feed_min_prefix_v6", 32), "limits.feed_min_prefix_v6", 0, 128),
    )
    if policy.max_seconds < policy.base_seconds:
        raise PolicyError("durations.max_seconds no puede ser menor que base_seconds")
    if not policy.internal_networks:
        raise PolicyError("internal_networks no puede estar vacia")
    return policy
