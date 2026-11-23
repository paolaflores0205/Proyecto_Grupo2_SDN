"""Hash de contrasenas compatible con werkzeug.security (formatos scrypt y pbkdf2).

El portal y la consola DTI guardan hashes con generate_password_hash de Werkzeug 3.0.1:
    "<metodo>$<sal>$<hash hex>"   p. ej. "scrypt:32768:8:1$Ab12...$9f3c..."
Esta implementacion usa hashlib de la biblioteca estandar para compartir exactamente
la misma verificacion en produccion y en pruebas aisladas.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

_SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _derive(method: str, salt: str, password: str) -> Optional[str]:
    name, *args = method.split(":")
    pwd, slt = password.encode("utf-8"), salt.encode("utf-8")
    if name == "scrypt":
        n, r, p = (int(x) for x in args) if args else (2 ** 15, 8, 1)
        return hashlib.scrypt(pwd, salt=slt, n=n, r=r, p=p, maxmem=132 * n * r * p).hex()
    if name == "pbkdf2":
        hash_name = args[0] if args else "sha256"
        iterations = int(args[1]) if len(args) > 1 else 600_000
        return hashlib.pbkdf2_hmac(hash_name, pwd, slt, iterations).hex()
    return None


def hash_password(password: str, method: str = "scrypt:32768:8:1", salt: Optional[str] = None) -> str:
    salt = salt or "".join(secrets.choice(_SALT_CHARS) for _ in range(16))
    digest = _derive(method, salt, password)
    if digest is None:
        raise ValueError(f"Metodo de hash no soportado: {method}")
    return f"{method}${salt}${digest}"


def verify_password(stored: str, password: str) -> bool:
    """True si la contrasena corresponde al hash. Nunca lanza: un hash malformado da False."""
    if not isinstance(stored, str) or not isinstance(password, str) or stored.count("$") < 2:
        return False
    method, salt, expected = stored.split("$", 2)
    try:
        digest = _derive(method, salt, password)
    except (ValueError, TypeError, OverflowError, MemoryError):
        return False
    return digest is not None and hmac.compare_digest(digest, expected)
