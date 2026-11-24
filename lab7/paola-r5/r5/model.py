"""Tipos de datos compartidos por el modulo R5."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple


class Action(str, Enum):
    """Accion que decide la politica para un evento."""
    BLOCK = "BLOCK"    # instalar drops en el switch de borde
    WATCH = "WATCH"    # vigilar: aun no alcanza el umbral para bloquear
    LOG = "LOG"        # solo registrar como incidente
    IGNORE = "IGNORE"  # evento sin indicadores: no es incidente


@dataclass(frozen=True)
class Alert:
    """Evento de Suricata ya validado y normalizado."""
    event_type: str                     # alert | dns | tls | http
    timestamp: datetime                 # hora del evento segun Suricata (UTC)
    src_ip: str
    dest_ip: str
    proto: str
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    signature_id: Optional[int] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = None      # 1 alta, 2 media, 3 baja (Suricata)
    domain: Optional[str] = None        # dns.rrname, tls.sni o http.hostname
    resolved_ips: Tuple[str, ...] = ()  # IPs de la respuesta DNS
    flow_id: Optional[int] = None
    in_iface: Optional[str] = None
    event_id: Optional[str] = None  # SHA-256 del registro EVE, sin campos de observacion


@dataclass(frozen=True)
class Decision:
    """Resultado de aplicar la politica a un evento."""
    action: Action
    reason: str
    policy_rule: int                    # orden de la regla de politica que decidio (1-6, 0 = ninguna)
    block_ips: Tuple[str, ...] = ()     # IPs externas a bloquear
    duration: int = 0                   # segundos del bloqueo
    internal_host: Optional[str] = None # host interno implicado (posible zombie)
    external_ip: Optional[str] = None   # extremo externo del evento
