"""Fixtures y dobles de prueba (almacen en memoria y cursor MySQL simulado) para R1/R2."""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from access import (
    Client,
    Resource,
    build_campus_matrix,
    hash_password,
)

TEST_PASSWORD = "ClavePrueba-Lab7-2026!"

LMS = Resource("lms", "192.168.10.101", 443, "tcp", False, "minima", "data")
NOTAS = Resource("notas", "192.168.10.102", 443, "tcp", True, "intermedia", "data")
ADMINISTRACION = Resource("administracion", "192.168.10.102", 8443, "tcp", True, "intermedia", "data")
CONSOLA_DTI = Resource("consola_dti", "192.168.0.20", 8443, "tcp", True, "critica", "management")

H1 = Client(ip="192.168.10.1", mac="fa:16:3e:53:96:3e", switch_dpid="00:00:00:00:00:00:00:02", in_port=3, name="h1")
H2 = Client(ip="192.168.10.2", mac="fa:16:3e:a1:30:9f", switch_dpid="00:00:00:00:00:00:00:02", in_port=4, name="h2")

_PRECOMPUTED_HASH = hash_password(TEST_PASSWORD, method="pbkdf2:sha256:1000")


class MemoryUserStore:
    """Almacen simulado de usuarios con los 4 roles reales de campus + cuenta inactiva."""

    def __init__(self) -> None:
        self.lookups: List[str] = []
        self._users: Dict[str, dict] = {
            "est01": {"id": 101, "role_id": 1, "role": "estudiante", "active": True, "password_hash": _PRECOMPUTED_HASH},
            "doc01": {"id": 102, "role_id": 2, "role": "docente", "active": True, "password_hash": _PRECOMPUTED_HASH},
            "adm01": {"id": 103, "role_id": 3, "role": "administrativo", "active": True, "password_hash": _PRECOMPUTED_HASH},
            "vis01": {"id": 104, "role_id": 4, "role": "visitante", "active": True, "password_hash": _PRECOMPUTED_HASH},
            "baja01": {"id": 105, "role_id": 1, "role": "estudiante", "active": False, "password_hash": _PRECOMPUTED_HASH},
        }

    def get_user(self, username: str) -> Optional[dict]:
        self.lookups.append(username)
        return self._users.get(username)


class FakeMySQLDatabase:
    """Simulador thread-safe de tablas users, roles y auth_events de sdn_g2."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users = MemoryUserStore()._users
        self.auth_events: List[Tuple[datetime, str, str, str]] = []
        self.locks_acquired: List[str] = []
        self.locks_released: List[str] = []
        self.queries: List[Tuple[str, tuple]] = []


class FakeMySQLCursor:
    """Cursor simulado que verifica consultas parametrizadas (%s) sin concatenacion."""

    def __init__(self, db: FakeMySQLDatabase) -> None:
        self._db = db
        self._last_row: Optional[dict] = None

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._db._lock:
            self._db.queries.append((sql, params))
            norm = " ".join(sql.split()).upper()
            if "SELECT GET_LOCK(" in norm:
                self._db.locks_acquired.append(params[0])
                self._last_row = {"locked": 1}
            elif "SELECT RELEASE_LOCK(" in norm:
                self._db.locks_released.append(params[0])
                self._last_row = {"released": 1}
            elif "FROM USERS U JOIN ROLES R" in norm:
                username = params[0]
                u = self._db.users.get(username)
                self._last_row = dict(u) if u else None
            elif norm.startswith("INSERT INTO AUTH_EVENTS"):
                occurred_at, username, terminal_ip, outcome = params
                self._db.auth_events.append((occurred_at, username, terminal_ip, outcome))
                self._last_row = None
            elif "SELECT COUNT(*) AS N FROM AUTH_EVENTS" in norm:
                since, now = params[0], params[1]
                rest = params[2:]
                has_user = "USERNAME = %S" in norm
                has_ip = "TERMINAL_IP = %S" in norm
                target_user = rest[0] if has_user else None
                target_ip = rest[1] if (has_user and has_ip) else (rest[0] if has_ip else None)
                count = sum(
                    1
                    for ts, u, ip, outcome in self._db.auth_events
                    if outcome == "invalid"
                    and since < ts <= now
                    and (
                        (target_user is not None and u == target_user)
                        or (target_ip is not None and ip == target_ip)
                    )
                )
                self._last_row = {"n": count}
            else:
                raise AssertionError(f"Consulta SQL no esperada en simulador: {sql}")

    def fetchone(self) -> Optional[dict]:
        return self._last_row


def make_matrix(extra_permissions=()):
    return build_campus_matrix(extra_permissions=extra_permissions)
