"""R1-01 y R1-02: validacion de credenciales compartida entre portal y pruebas."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Optional, Protocol

from .passwords import hash_password, verify_password

GENERIC_ERROR = "Usuario o contraseña inválidos."
USERNAME = re.compile(r"[a-z0-9_]{1,64}")
# Hash de una clave aleatoria: si el usuario no existe se compara contra este,
# mitigando enumeracion por tiempo de respuesta.
DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


class UserStore(Protocol):
    def get_user(self, username: str) -> Optional[dict]:
        """Devuelve {'id', 'password_hash', 'role', 'active', 'role_id' (opcional)} o None."""


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    user_id: Optional[int]
    role: Optional[str]
    message: str
    role_id: Optional[int] = None


_REJECT = AuthResult(False, None, None, GENERIC_ERROR, None)


def validate_credentials(store: UserStore, username: object, password: object) -> AuthResult:
    """Autentica y devuelve id y rol, o un rechazo con el mismo mensaje en todos los casos."""
    name = username.strip().lower() if isinstance(username, str) else ""
    if not USERNAME.fullmatch(name) or not isinstance(password, str) or not 1 <= len(password) <= 256:
        return _REJECT
    user = store.get_user(name)
    valid = verify_password(user["password_hash"] if user else DUMMY_HASH, password)
    if not valid or not user or not user.get("active"):
        return _REJECT
    return AuthResult(True, user["id"], user["role"], "Acceso concedido", role_id=user.get("role_id"))
