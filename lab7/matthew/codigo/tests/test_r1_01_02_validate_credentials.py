"""R1-01 y R1-02: validate_credentials, hashes Werkzeug y adaptador MySQL parametrizado."""
import unittest

from access import (
    GENERIC_ERROR,
    MySQLUserStore,
    hash_password,
    validate_credentials,
    verify_password,
)

from .access_helpers import FakeMySQLCursor, FakeMySQLDatabase, MemoryUserStore, TEST_PASSWORD

try:
    from werkzeug.security import generate_password_hash
except ImportError:
    generate_password_hash = None


class ValidCredentials(unittest.TestCase):
    def test_1_1_1_valid_user_gets_id_and_role(self):
        """1.1.1 Normal (R1-01): usuarios activos de los 4 roles reales obtienen id y codigo de rol."""
        store = MemoryUserStore()
        expected = [
            ("est01", 101, "estudiante"),
            ("doc01", 102, "docente"),
            ("adm01", 103, "administrativo"),
            ("vis01", 104, "visitante"),
        ]
        for user, uid, role in expected:
            with self.subTest(user=user):
                result = validate_credentials(store, user, TEST_PASSWORD)
                self.assertTrue(result.ok)
                self.assertEqual((result.user_id, result.role), (uid, role))

    def test_1_1_3_username_is_normalized(self):
        """1.1.3 Limite (R1-01): el usuario se normaliza en minusculas y sin espacios."""
        result = validate_credentials(MemoryUserStore(), "  DOC01 ", TEST_PASSWORD)
        self.assertEqual((result.ok, result.role), (True, "docente"))


class InvalidCredentials(unittest.TestCase):
    def test_1_1_2_all_invalid_attempts_rejected_alike(self):
        """1.1.2 Invalido (R1-02): clave erronea, inexistente, vacios e inyeccion -> rechazo uniforme."""
        store = MemoryUserStore()
        cases = [
            ("est01", "clave-equivocada"),
            ("noexiste", TEST_PASSWORD),
            ("", ""),
            ("est01", ""),
            ("", TEST_PASSWORD),
            ("' OR '1'='1", "' OR '1'='1"),
            ("est01' --", TEST_PASSWORD),
            (None, None),
            ("est01", "x" * 257),
        ]
        for user, pwd in cases:
            with self.subTest(user=user, pwd=str(pwd)[:20]):
                result = validate_credentials(store, user, pwd)
                self.assertFalse(result.ok)
                self.assertIsNone(result.role)
                self.assertIsNone(result.user_id)
                self.assertEqual(result.message, GENERIC_ERROR)

    def test_1_1_4_inactive_user_rejected(self):
        """1.1.4 Invalido (R1-01): cuenta desactivada con clave correcta -> mismo rechazo uniforme."""
        result = validate_credentials(MemoryUserStore(), "baja01", TEST_PASSWORD)
        self.assertEqual((result.ok, result.message), (False, GENERIC_ERROR))

    def test_1_1_5_injection_never_reaches_the_store(self):
        """1.1.5 Invalido (R1-02): caracteres de SQLi se rechazan antes de consultar la base."""
        store = MemoryUserStore()
        validate_credentials(store, "' OR '1'='1", "x")
        validate_credentials(store, "est01'; DROP TABLE users;--", "x")
        validate_credentials(store, "noexiste", "x")
        self.assertEqual(store.lookups, ["noexiste"])


class PasswordHashesAndSQLAdapter(unittest.TestCase):
    def test_1_1_6_malformed_hash_is_false(self):
        """1.1.6 Invalido (R1-02): hash danado o metodo desconocido nunca autentica ni lanza excepcion."""
        for stored in ("", "sin-separadores", "md5$sal$abc", "scrypt:x:y:z$sal$abc", None):
            with self.subTest(stored=stored):
                self.assertFalse(verify_password(stored, TEST_PASSWORD))

    @unittest.skipIf(generate_password_hash is None, "Werkzeug no instalado en este entorno")
    def test_1_1_7_compatible_with_werkzeug_hashes(self):
        """1.1.7 Integracion (R1-01): compatibilidad exacta con hashes scrypt y pbkdf2 de Werkzeug."""
        for method in ("scrypt", "pbkdf2:sha256:1000"):
            with self.subTest(method=method):
                stored = generate_password_hash(TEST_PASSWORD, method=method)
                self.assertTrue(verify_password(stored, TEST_PASSWORD))
                self.assertFalse(verify_password(stored, "otra"))
        self.assertTrue(verify_password(hash_password(TEST_PASSWORD, method="pbkdf2:sha256:1000"), TEST_PASSWORD))

    def test_1_1_8_mysql_user_store_parameterized_query(self):
        """1.1.8 Integracion simulada (R1-01/R1-02): MySQLUserStore usa consulta parametrizada %s."""
        fake_db = FakeMySQLDatabase()
        store = MySQLUserStore(FakeMySQLCursor(fake_db))
        ok_res = validate_credentials(store, "doc01", TEST_PASSWORD)
        self.assertTrue(ok_res.ok)
        self.assertEqual((ok_res.user_id, ok_res.role, ok_res.role_id), (102, "docente", 2))
        bad_res = validate_credentials(store, "baja01", TEST_PASSWORD)
        self.assertFalse(bad_res.ok)
        self.assertEqual(bad_res.message, GENERIC_ERROR)
        # Verificar que toda consulta uso %s y nunca interpolo el username en la cadena SQL
        self.assertEqual(len(fake_db.queries), 2)
        for sql, params in fake_db.queries:
            self.assertIn("WHERE u.username = %s", sql)
            self.assertEqual(len(params), 1)
            self.assertNotIn(params[0], sql)


if __name__ == "__main__":
    unittest.main()
