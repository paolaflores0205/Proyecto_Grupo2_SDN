"""R5-04 is_malicious_domain: dominio, subdominio y mayusculas."""
import unittest

from .helpers import make_intel


class MaliciousDomain(unittest.TestCase):
    def setUp(self):
        self.intel = make_intel()

    def test_5_4_1_domain_subdomain_uppercase(self):
        """5.4.1 Limite: el dominio, un subdominio y la version en mayusculas son maliciosos."""
        for name in ("malware.example", "descargas.malware.example", "MALWARE.EXAMPLE",
                     "malware.example.", "  Malware.Example  "):
            with self.subTest(name=name):
                self.assertTrue(self.intel.is_malicious_domain(name))

    def test_5_4_2_lookalikes_are_legitimate(self):
        """5.4.2 Falso positivo: dominios parecidos o legitimos no se marcan."""
        for name in ("notmalware.example", "malware.example.com", "example", "pucp.edu.pe",
                     "c2.test.pucp.edu.pe"):
            with self.subTest(name=name):
                self.assertFalse(self.intel.is_malicious_domain(name))

    def test_5_4_3_invalid_input(self):
        """5.4.3 Invalido: vacio, None, una IP o caracteres raros devuelven False."""
        for value in ("", None, "203.0.113.66", "mal ware.example", "-malware.example", 42):
            with self.subTest(value=value):
                self.assertFalse(self.intel.is_malicious_domain(value))


if __name__ == "__main__":
    unittest.main()
