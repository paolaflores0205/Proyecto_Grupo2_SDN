"""R5-03 is_malicious_ip: lista negra, IP legitima y lista blanca."""
import ipaddress
import unittest

from r5 import ThreatIntel

from .helpers import make_intel


class MaliciousIp(unittest.TestCase):
    def setUp(self):
        self.intel = make_intel()

    def test_5_3_1_three_reference_addresses(self):
        """5.3.1 Normal / falso positivo: solo la IP de la lista negra es maliciosa; la del DNS nunca."""
        self.assertTrue(self.intel.is_malicious_ip("203.0.113.66"))   # lista negra
        self.assertFalse(self.intel.is_malicious_ip("203.0.113.2"))   # legitima (no listada)
        self.assertFalse(self.intel.is_malicious_ip("192.168.3.31"))  # DNS de la PUCP (lista blanca)

    def test_5_3_2_inside_blacklisted_network(self):
        """5.3.2 Limite: una IP dentro de un bloque CIDR negro es maliciosa; la de al lado no."""
        self.assertTrue(self.intel.is_malicious_ip("203.0.113.130"))   # dentro de 203.0.113.128/26
        self.assertTrue(self.intel.is_malicious_ip("203.0.113.191"))   # ultima del bloque
        self.assertFalse(self.intel.is_malicious_ip("203.0.113.192"))  # primera fuera

    def test_5_3_3_whitelist_wins_over_blacklist(self):
        """5.3.3 Falso positivo: si una IP esta en ambas listas, gana la blanca."""
        intel = ThreatIntel([ipaddress.ip_network("192.168.3.31/32")], "192.168.3.0/24")
        self.assertFalse(intel.is_malicious_ip("192.168.3.31"))
        self.assertTrue(intel.is_malicious_ip("192.168.3.32"))

    def test_5_3_4_invalid_input(self):
        """5.3.4 Invalido: textos que no son IP devuelven False sin excepcion."""
        for value in ("", "abc", "300.1.1.1", None, "203.0.113.66/32"):
            with self.subTest(value=value):
                self.assertFalse(self.intel.is_malicious_ip(value))


if __name__ == "__main__":
    unittest.main()
