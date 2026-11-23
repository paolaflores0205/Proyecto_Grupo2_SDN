"""Adaptadores parametrizados a MySQL (sdn_g2) para produccion y pruebas con cursor simulado."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, List, Optional, Tuple

from .authz import CAMPUS_ROLES, DEFAULT_RESOURCES, AccessMatrix, Resource, normalize_role


class MySQLUserStore:
    """Adaptador de UserStore sobre las tablas users + roles de sdn_g2."""

    def __init__(self, cursor: Any) -> None:
        self._cur = cursor

    def get_user(self, username: str) -> Optional[dict]:
        self._cur.execute(
            "SELECT u.id, u.password_hash, u.role_id, r.code AS role, u.active "
            "FROM users u JOIN roles r ON r.id = u.role_id "
            "WHERE u.username = %s",
            (username,),
        )
        row = self._cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "password_hash": row["password_hash"],
            "role_id": row["role_id"],
            "role": row["role"],
            "active": bool(row["active"]),
        }


class MySQLFailureStore:
    """Adaptador de FailureStore persistido en auth_events con GET_LOCK determinista."""

    def __init__(self, cursor: Any) -> None:
        self._cur = cursor

    def acquire_locks(self, username: str, terminal_ip: str, timeout: int = 5) -> List[str]:
        """Adquiere locks por cuenta y terminal en orden determinista para evitar deadlocks."""
        names = sorted({f"sdn-r1-term-{terminal_ip}", f"sdn-r1-acct-{(username or '').strip().lower()}"})
        acquired: List[str] = []
        for lock_name in names:
            self._cur.execute("SELECT GET_LOCK(%s, %s) AS locked", (lock_name, timeout))
            row = self._cur.fetchone()
            if not row or row.get("locked") != 1:
                self.release_locks(acquired)
                raise RuntimeError(f"No se pudo adquirir lock de concurrencia: {lock_name}")
            acquired.append(lock_name)
        return acquired

    def release_locks(self, lock_names: Iterable[str]) -> None:
        for lock_name in reversed(list(lock_names)):
            self._cur.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))

    def record_failure(self, username: str, terminal_ip: str, now: datetime) -> None:
        self._cur.execute(
            "INSERT INTO auth_events(occurred_at, username, terminal_ip, outcome) "
            "VALUES(%s, %s, %s, %s)",
            (now.replace(tzinfo=None), (username or "")[:64], (terminal_ip or "")[:45], "invalid"),
        )

    def count_failures(
        self,
        since: datetime,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> int:
        s_naive = since.replace(tzinfo=None)
        n_naive = now.replace(tzinfo=None)
        clauses: List[str] = []
        params: List[Any] = [s_naive, n_naive]
        if username is not None:
            clauses.append("username = %s")
            params.append(username.strip().lower())
        if terminal_ip is not None:
            clauses.append("terminal_ip = %s")
            params.append(terminal_ip)
        if not clauses:
            return 0
        where_target = "(" + " OR ".join(clauses) + ")"
        self._cur.execute(
            f"SELECT COUNT(*) AS n FROM auth_events "
            f"WHERE outcome = 'invalid' AND occurred_at > %s AND occurred_at <= %s AND {where_target}",
            tuple(params),
        )
        row = self._cur.fetchone()
        return int(row["n"]) if row else 0


def load_access_matrix_from_rows(
    policy_rows: Iterable[dict],
    extra_denies: Iterable[Tuple[str, str]] = (),
) -> AccessMatrix:
    """Construye AccessMatrix a partir de las filas role_permissions JOIN resources JOIN roles."""
    resources_by_code = {r.code: r for r in DEFAULT_RESOURCES}
    roles = set(CAMPUS_ROLES) | {"admin_dti"}
    permissions: List[Tuple[str, str, bool]] = [("admin_dti", "consola_dti", True)]

    for row in policy_rows:
        role_code = normalize_role(row.get("role_code") or row.get("role") or "")
        res_code = (row.get("code") or "").strip().lower()
        if not role_code or not res_code:
            continue
        roles.add(role_code)
        if res_code not in resources_by_code:
            resources_by_code[res_code] = Resource(
                code=res_code,
                ip=str(row.get("ip_address", "")),
                port=int(row.get("port", 0)),
                transport=str(row.get("transport", "tcp")).lower(),
                privileged=bool(row.get("privileged", False)),
                protection="intermedia" if row.get("privileged") else "minima",
                plane="data",
            )
        allowed = bool(
            row.get("allowed")
            and row.get("deployment_state", "active") == "active"
            and str(row.get("transport", "TCP")).upper() == "TCP"
        )
        permissions.append((role_code, res_code, allowed))

    for r_code, res_code in extra_denies:
        permissions.append((normalize_role(r_code), res_code.strip().lower(), False))

    return AccessMatrix(roles=roles, resources=resources_by_code.values(), permissions=permissions)
