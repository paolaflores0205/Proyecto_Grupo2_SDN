"""Vinculacion de la consola DTI (vnrt_admin_paso7.py: identity() y authorized()) con R2-01.

La consola DTI corre en 192.168.0.20:8443 sobre la red de gestion 192.168.0.0/24 y consulta
las tablas admin_accounts y admin_sessions, completamente separada de los roles de campus.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from .authz import AccessDecision, Decision


@dataclass(frozen=True)
class DTIAccount:
    admin_id: int
    username: str
    active: bool
    source_ip: str


def evaluate_dti_console_access(
    account: Optional[DTIAccount],
    request_ip: str,
    management_cidr: str = "192.168.0.0/24",
) -> AccessDecision:
    """Evalua acceso a consola_dti replicando la semantica de identity() + authorized()."""
    try:
        ip_obj = ipaddress.ip_address(request_ip)
        mgmt_net = ipaddress.ip_network(management_cidr, strict=False)
    except ValueError:
        return AccessDecision(Decision.DENY, "desconocido", "consola_dti", "IP de origen invalida")

    if ip_obj not in mgmt_net:
        role_label = account.username if account else "cliente_datos"
        return AccessDecision(
            Decision.DENY,
            role_label,
            "consola_dti",
            "Acceso a consola DTI restringido a la red de gestion",
        )

    if account is None:
        return AccessDecision(
            Decision.DENY,
            "sin_sesion_dti",
            "consola_dti",
            "Sin sesion valida en admin_accounts/admin_sessions",
        )

    if not account.active:
        return AccessDecision(
            Decision.DENY,
            account.username,
            "consola_dti",
            "Cuenta DTI desactivada en admin_accounts",
        )

    if account.source_ip != request_ip:
        return AccessDecision(
            Decision.DENY,
            account.username,
            "consola_dti",
            "IP de origen no coincide con la sesion DTI registrada",
        )

    return AccessDecision(
        Decision.PERMIT,
        "admin_dti",
        "consola_dti",
        "Autorizado por identity()/authorized() sobre admin_accounts en red de gestion",
    )
