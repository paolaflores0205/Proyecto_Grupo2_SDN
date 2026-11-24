"""R5-05: reglas de bloqueo para el switch de borde (Floodlight Static Flow Pusher)."""
from __future__ import annotations

import ipaddress
from typing import Dict, Iterable, List

from .policy import Policy


class RuleRejected(ValueError):
    """La IP no se puede bloquear en el borde (invalida, interna o en lista blanca)."""


def rule_names(ip: str, policy: Policy) -> Dict[str, str]:
    """Nombres fijos por IP: la misma IP siempre produce los mismos nombres."""
    base = f"{policy.rule_prefix}-{ip.replace('.', '-')}"
    return {"in": base + "-in", "out": base + "-out"}


def build_perimeter_rule(ip: str, policy: Policy, duration: int,
                         existing: Iterable[str] = ()) -> List[dict]:
    """Construye los drops de entrada y salida para una IP externa.

    - Entrada: lo que llega por el puerto de borde con ipv4_src = ip.
    - Salida: todo lo que va hacia ipv4_dst = ip.
    Devuelve solo las reglas cuyo nombre no esta en `existing` (no duplica).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError) as exc:
        raise RuleRejected(f"IP invalida: {ip!r}") from exc
    if addr.version != 4:
        raise RuleRejected("Solo se bloquean IPv4 en esta version")
    ip = str(addr)
    if policy.is_internal(ip):
        raise RuleRejected(f"{ip} es interna: un host interno no se bloquea automaticamente")
    if policy.is_whitelisted(ip):
        raise RuleRejected(f"{ip} esta en la lista blanca")
    if type(duration) is not int or not 1 <= duration <= 65535:
        raise RuleRejected("La duracion debe estar entre 1 y 65535 s (hard_timeout de OpenFlow)")

    names = rule_names(ip, policy)
    common = {
        "switch": policy.edge_dpid, "table": "0", "priority": str(policy.priority),
        "active": "true", "idle_timeout": "0", "hard_timeout": str(duration),
        "eth_type": "0x0800", "actions": "",  # sin acciones = drop
    }
    rules = [
        dict(common, name=names["in"], in_port=str(policy.edge_port), ipv4_src=f"{ip}/32"),
        dict(common, name=names["out"], ipv4_dst=f"{ip}/32"),
    ]
    present = set(existing)
    return [r for r in rules if r["name"] not in present]
