"""R2-01 y R2-02: decision de acceso rol -> recurso con DENY por defecto.

Alineado con los codigos reales de MySQL (sdn_g2):
- Roles de campus (plano de datos): estudiante, docente, administrativo, visitante.
- Recursos de campus (plano de datos): lms (h5:443), notas (h4:443), administracion (h4:8443).
- Recurso critico de gestion: consola_dti (app 192.168.0.20:8443), separado del recurso
  academico administracion y gestionado exclusivamente por admin_accounts en sdn-admin.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Optional, Tuple


class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"


CAMPUS_ROLES = frozenset({"estudiante", "docente", "administrativo", "visitante"})

ROLE_CODE_MAP: Dict[str, str] = {
    "estudiante": "estudiante",
    "docente": "docente",
    "administrativo": "administrativo",
    "visitante": "visitante",
    "administrador dti": "admin_dti",
    "admin_dti": "admin_dti",
}


def normalize_role(role: str) -> str:
    if not isinstance(role, str):
        return ""
    key = role.strip().lower()
    return ROLE_CODE_MAP.get(key, key)


@dataclass(frozen=True)
class Resource:
    code: str
    ip: str
    port: int
    transport: str = "tcp"
    privileged: bool = False
    protection: str = "minima"  # minima | intermedia | critica
    plane: str = "data"  # data | management


@dataclass(frozen=True)
class AccessDecision:
    decision: Decision
    role: str
    resource: str
    reason: str


DEFAULT_RESOURCES: Tuple[Resource, ...] = (
    Resource("lms", "192.168.10.101", 443, "tcp", False, "minima", "data"),
    Resource("notas", "192.168.10.102", 443, "tcp", True, "intermedia", "data"),
    Resource("administracion", "192.168.10.102", 8443, "tcp", True, "intermedia", "data"),
    Resource("consola_dti", "192.168.0.20", 8443, "tcp", True, "critica", "management"),
)

DEFAULT_PERMISSIONS: Tuple[Tuple[str, str, bool], ...] = (
    ("estudiante", "lms", True),
    ("estudiante", "notas", False),
    ("estudiante", "administracion", False),
    ("docente", "lms", True),
    ("docente", "notas", True),
    ("docente", "administracion", False),
    ("administrativo", "lms", False),
    ("administrativo", "notas", False),
    ("administrativo", "administracion", True),
    ("visitante", "lms", False),
    ("visitante", "notas", False),
    ("visitante", "administracion", False),
    ("admin_dti", "consola_dti", True),
)


class AccessMatrix:
    """Roles, inventario de recursos y permisos (rol, recurso, permitido)."""

    def __init__(
        self,
        roles: Iterable[str],
        resources: Iterable[Resource],
        permissions: Iterable[Tuple[str, str, bool]],
    ):
        self.roles = frozenset(normalize_role(r) for r in roles)
        self.resources: Dict[str, Resource] = {r.code.strip().lower(): r for r in resources}
        self._allow: Dict[Tuple[str, str], bool] = {}
        for role, code, allowed in permissions:
            key = (normalize_role(role), code.strip().lower())
            # Si coexisten PERMIT y DENY para el mismo par, gana siempre DENY.
            self._allow[key] = self._allow.get(key, True) and bool(allowed)

    def entry(self, role: str, code: str) -> Optional[bool]:
        return self._allow.get((normalize_role(role), code.strip().lower()))


def build_campus_matrix(
    extra_permissions: Iterable[Tuple[str, str, bool]] = (),
    include_dti_role: bool = True,
) -> AccessMatrix:
    """Construye la matriz oficial del Grupo 2 con los codigos reales desplegados."""
    roles = set(CAMPUS_ROLES)
    if include_dti_role:
        roles.add("admin_dti")
    perms = list(DEFAULT_PERMISSIONS) + list(extra_permissions)
    return AccessMatrix(roles=roles, resources=DEFAULT_RESOURCES, permissions=perms)


def evaluate_access(matrix: AccessMatrix, role: str, resource: str) -> AccessDecision:
    """PERMIT solo si rol y recurso existen y la matriz lo permite; todo lo demas es DENY."""
    norm_role = normalize_role(role)
    norm_res = resource.strip().lower() if isinstance(resource, str) else ""
    if norm_role not in matrix.roles:
        return AccessDecision(Decision.DENY, role, resource, "Rol no registrado")
    res = matrix.resources.get(norm_res)
    if res is None:
        return AccessDecision(Decision.DENY, role, resource, "Recurso fuera del inventario")
    # Separacion estricta: ningun rol de campus (incluido 'administrativo') accede a consola_dti.
    if res.plane == "management" and norm_role in CAMPUS_ROLES:
        return AccessDecision(
            Decision.DENY,
            role,
            resource,
            "Rol de campus sin permiso sobre recurso critico de gestion",
        )
    allowed = matrix.entry(norm_role, norm_res)
    if allowed:
        return AccessDecision(Decision.PERMIT, role, resource, "Permitido por la matriz de roles")
    if allowed is False:
        return AccessDecision(Decision.DENY, role, resource, "Denegado explicitamente en la matriz")
    if res.protection == "critica":
        return AccessDecision(Decision.DENY, role, resource, "Rol sin permiso sobre recurso critico")
    return AccessDecision(Decision.DENY, role, resource, "Rol sin permiso sobre el recurso")
