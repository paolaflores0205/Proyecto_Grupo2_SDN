"""R1-03: bloqueo tras N = 8 fallos en ventana de 900 s por cuenta o por terminal, concurrencia y SQL."""
import threading
import unittest
from datetime import datetime, timedelta, timezone

from access import LoginGuard, MySQLFailureStore

from .access_helpers import FakeMySQLCursor, FakeMySQLDatabase

T0 = datetime(2026, 11, 22, 0, 0, tzinfo=timezone.utc)
H1, H2 = "192.168.10.1", "192.168.10.2"


def fail(guard, n, user="est01", ip=H1, start=T0, step=timedelta(seconds=10)):
    for i in range(n):
        guard.register_failed_attempt(user, ip, start + i * step)
    return start + (n - 1) * step


class Lockout(unittest.TestCase):
    def test_1_2_1_lock_at_exactly_n(self):
        """1.2.1 Limite (R1-03): con N-1=7 fallos sigue habilitada; al N=8 queda bloqueada."""
        guard = LoginGuard()  # N = 8 en 900 s
        last = fail(guard, 7)
        self.assertFalse(guard.is_locked(last, username="est01"))
        guard.register_failed_attempt("est01", H1, last + timedelta(seconds=10))
        self.assertTrue(guard.is_locked(last + timedelta(seconds=10), username="est01"))

    def test_1_2_2_unlocks_after_window(self):
        """1.2.2 Limite (R1-03): pasados 900 s desde los fallos, la cuenta vuelve a habilitarse."""
        guard = LoginGuard()
        last = fail(guard, 8)
        self.assertTrue(guard.is_locked(last, username="est01"))
        # El ultimo fallo fue en T0 + 70 s; a T0 + 971 s ya vencieron los 8 fallos
        self.assertFalse(guard.is_locked(T0 + timedelta(seconds=971), username="est01"))

    def test_1_2_3_account_locked_from_any_terminal(self):
        """1.2.3 Normal (R1-03): 4 fallos desde h1 + 4 desde h2 bloquean la cuenta (8 total)."""
        guard = LoginGuard()
        fail(guard, 4, ip=H1)
        last = fail(guard, 4, ip=H2, start=T0 + timedelta(minutes=1))
        self.assertTrue(guard.is_locked(last, username="est01"))
        self.assertEqual(guard.lock_scope(last, username="est01", terminal_ip=H1), "account")
        self.assertFalse(guard.is_locked(last, terminal_ip=H1))

    def test_1_2_4_terminal_locked_for_password_spraying(self):
        """1.2.4 Normal (R1-03): un terminal que prueba 8 cuentas queda bloqueado (password spraying)."""
        guard = LoginGuard()
        for i in range(8):
            guard.register_failed_attempt(f"usuario{i}", H1, T0 + timedelta(seconds=i))
        now = T0 + timedelta(seconds=8)
        self.assertTrue(guard.is_locked(now, username="otro", terminal_ip=H1))
        self.assertEqual(guard.lock_scope(now, username="otro", terminal_ip=H1), "terminal")
        self.assertFalse(guard.is_locked(now, username="usuario0"))

    def test_1_2_5_other_accounts_unaffected(self):
        """1.2.5 Falso positivo (R1-03): bloquear est01 en h1 no afecta a doc01 en h2."""
        guard = LoginGuard()
        last = fail(guard, 8)
        self.assertFalse(guard.is_locked(last, username="doc01", terminal_ip=H2))

    def test_1_2_6_concurrent_attempts_preserve_count(self):
        """1.2.6 Concurrencia (R1-03): 12 hilos concurrentes registran 12 fallos sin perder intentos."""
        guard = LoginGuard()
        barrier = threading.Barrier(12)

        def worker(idx: int) -> None:
            barrier.wait()
            guard.register_failed_attempt("est01", H1, T0 + timedelta(milliseconds=idx))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        now = T0 + timedelta(seconds=1)
        self.assertEqual(guard.failures(now, username="est01"), 12)
        self.assertTrue(guard.is_locked(now, username="est01", terminal_ip=H1))

    def test_1_2_7_sql_persistence_and_deterministic_locks(self):
        """1.2.7 Integracion simulada (R1-03): MySQLFailureStore persiste en auth_events y sobrevive reinicio."""
        fake_db = FakeMySQLDatabase()
        store1 = MySQLFailureStore(FakeMySQLCursor(fake_db))
        locks = store1.acquire_locks("est01", H1)
        self.assertEqual(locks, ["sdn-r1-acct-est01", "sdn-r1-term-192.168.10.1"])
        guard1 = LoginGuard(store=store1)
        last = fail(guard1, 8, user="est01", ip=H1)
        store1.release_locks(locks)

        # Nuevo LoginGuard (simula reinicio de proceso) lee el estado persistido en SQL
        guard2 = LoginGuard(store=MySQLFailureStore(FakeMySQLCursor(fake_db)))
        self.assertTrue(guard2.is_locked(last, username="est01", terminal_ip=H2))
        self.assertFalse(guard2.is_locked(T0 + timedelta(seconds=971), username="est01", terminal_ip=H2))
        self.assertEqual(fake_db.locks_acquired, ["sdn-r1-acct-est01", "sdn-r1-term-192.168.10.1"])
        self.assertEqual(fake_db.locks_released, ["sdn-r1-term-192.168.10.1", "sdn-r1-acct-est01"])


if __name__ == "__main__":
    unittest.main()
