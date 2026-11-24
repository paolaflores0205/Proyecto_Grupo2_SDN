"""R5-05 build_perimeter_rule: drops de entrada y salida en el borde, sin duplicar."""
import unittest

from r5 import RuleRejected, build_perimeter_rule

from .helpers import POLICY


class PerimeterRule(unittest.TestCase):
    def test_5_5_1_in_and_out_rules(self):
        """5.5.1 Normal: se generan dos drops en sw5 (entrada por p3 y salida hacia la IP)."""
        rules = build_perimeter_rule("203.0.113.66", POLICY, 300)
        self.assertEqual([r["name"] for r in rules], ["g2-r5-203-0-113-66-in", "g2-r5-203-0-113-66-out"])
        rin, rout = rules
        for r in rules:
            self.assertEqual(r["switch"], "00:00:00:00:00:00:00:05")
            self.assertEqual((r["priority"], r["hard_timeout"], r["idle_timeout"]), ("32000", "300", "0"))
            self.assertEqual((r["eth_type"], r["actions"], r["active"]), ("0x0800", "", "true"))
        self.assertEqual((rin["in_port"], rin["ipv4_src"]), ("3", "203.0.113.66/32"))
        self.assertNotIn("in_port", rout)
        self.assertEqual(rout["ipv4_dst"], "203.0.113.66/32")

    def test_5_5_2_existing_rules_not_duplicated(self):
        """5.5.2 Limite: si las reglas ya existen no se generan de nuevo; si falta una, solo esa."""
        names = [r["name"] for r in build_perimeter_rule("203.0.113.66", POLICY, 300)]
        self.assertEqual(build_perimeter_rule("203.0.113.66", POLICY, 300, existing=names), [])
        only_out = build_perimeter_rule("203.0.113.66", POLICY, 300, existing=names[:1])
        self.assertEqual([r["name"] for r in only_out], names[1:])

    def test_5_5_3_protected_addresses_rejected(self):
        """5.5.3 Invalido: no se bloquean IPs internas, de la lista blanca, invalidas ni IPv6."""
        for ip in ("192.168.10.3", "192.168.3.31", "8.8.4.4", "no-es-ip", "2001:db8::1"):
            with self.subTest(ip=ip):
                with self.assertRaises(RuleRejected):
                    build_perimeter_rule(ip, POLICY, 300)

    def test_5_5_4_duration_limits(self):
        """5.5.4 Limite: la duracion debe caber en el hard_timeout de OpenFlow (1-65535 s)."""
        self.assertEqual(build_perimeter_rule("203.0.113.66", POLICY, 65535)[0]["hard_timeout"], "65535")
        for bad in (0, 65536, "300", 1.5):
            with self.subTest(duration=bad):
                with self.assertRaises(RuleRejected):
                    build_perimeter_rule("203.0.113.66", POLICY, bad)


if __name__ == "__main__":
    unittest.main()
