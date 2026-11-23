"""R1-03: bloqueo tras N = 8 intentos fallidos en ventana de 900 s por cuenta o por terminal.

Cambio de comportamiento documentado para Lab 7:
- Portal previo (vnrt_portal_paso5.py): 8 fallos en 15 min solo por terminal_ip.
- Version integrada: 8 fallos en 900 s por cuenta (username) O por terminal (terminal_ip),
  persistido en SQL (auth_events) en produccion e inyectable con MemoryFailureStore en tests.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Protocol, Tuple


class FailureStore(Protocol):
    def record_failure(self, username: str, terminal_ip: str, now: datetime) -> None:
        """Registra un intento fallido con timestamp UTC."""

    def count_failures(
        self,
        since: datetime,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> int:
        """Cuenta fallos estrictamente en (since, now] para username y/o terminal_ip."""


class MemoryFailureStore:
    """Almacen en memoria seguro para hilos, usado exclusivamente en pruebas unitarias."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: List[Tuple[datetime, str, str]] = []

    def record_failure(self, username: str, terminal_ip: str, now: datetime) -> None:
        with self._lock:
            self._events.append((now, (username or "").strip().lower(), terminal_ip))

    def count_failures(
        self,
        since: datetime,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> int:
        name = (username or "").strip().lower() if username is not None else None
        with self._lock:
            return sum(
                1
                for t, u, ip in self._events
                if since < t <= now
                and (
                    (name is not None and u == name)
                    or (terminal_ip is not None and ip == terminal_ip)
                )
            )


@dataclass
class LoginGuard:
    max_failures: int = 8
    window: timedelta = timedelta(seconds=900)
    store: FailureStore = field(default_factory=MemoryFailureStore)

    def register_failed_attempt(self, username: str, terminal_ip: str, now: datetime) -> None:
        self.store.record_failure((username or "").strip().lower(), terminal_ip, now)

    def failures(
        self,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> int:
        since = now - self.window
        name = (username or "").strip().lower() if username is not None else None
        return self.store.count_failures(since, now, username=name, terminal_ip=terminal_ip)

    def lock_scope(
        self,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> Optional[str]:
        """Devuelve el alcance interno del bloqueo ('account', 'terminal', 'both' o None)."""
        by_user = bool(username) and self.failures(now, username=username) >= self.max_failures
        by_ip = bool(terminal_ip) and self.failures(now, terminal_ip=terminal_ip) >= self.max_failures
        if by_user and by_ip:
            return "both"
        if by_user:
            return "account"
        if by_ip:
            return "terminal"
        return None

    def is_locked(
        self,
        now: datetime,
        username: Optional[str] = None,
        terminal_ip: Optional[str] = None,
    ) -> bool:
        """Bloqueado si la cuenta O el terminal acumulan max_failures fallos en la ventana."""
        return self.lock_scope(now, username=username, terminal_ip=terminal_ip) is not None
