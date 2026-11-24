"""R5-01 parse_ids_alert: alertas correctas se leen; las incorrectas se descartan sin caerse."""
import json
import unittest
from datetime import datetime, timezone

from r5 import parse_ids_alert

from .helpers import REAL_ALERT, REAL_HTTP, REAL_TLS, alert_line, dns_answer_line, tls_line


class ParseValidAlerts(unittest.TestCase):
    def test_5_1_1_real_alert_fields(self):
        """5.1.1 Normal: una alerta real de la maqueta entrega IPs, puertos, protocolo, firma y severidad."""
        a = parse_ids_alert(REAL_ALERT)
        self.assertIsNotNone(a)
        self.assertEqual((a.src_ip, a.src_port, a.dest_ip, a.dest_port), ("192.168.10.2", 58938, "192.168.10.10", 443))
        self.assertEqual(a.proto, "TCP")
        self.assertEqual(a.signature_id, 2260001)
        self.assertEqual(a.signature, "SURICATA Applayer Wrong direction first Data")
        self.assertEqual(a.severity, 3)
        self.assertEqual(a.timestamp, datetime(2026, 11, 15, 20, 37, 48, 340946, tzinfo=timezone.utc))

    def test_5_1_2_bytes_input(self):
        """5.1.2 Normal: la misma linea en bytes (como la lee el colector) da el mismo resultado."""
        self.assertEqual(parse_ids_alert(REAL_ALERT.encode()), parse_ids_alert(REAL_ALERT))

    def test_5_1_3_dns_answer(self):
        """5.1.3 Normal: una respuesta DNS entrega el dominio normalizado y las IPs resueltas, sin duplicados."""
        line = dns_answer_line("WWW.C2.Test.", answers=["198.51.100.77", "198.51.100.78"],
                               grouped={"A": ["198.51.100.77"]})
        a = parse_ids_alert(line)
        self.assertEqual(a.domain, "www.c2.test")
        self.assertEqual(a.resolved_ips, ("198.51.100.77", "198.51.100.78"))

    def test_5_1_4_dns_v3_queries(self):
        """5.1.4 Limite: el formato DNS v3 (lista 'queries') tambien se entiende."""
        raw = json.loads(dns_answer_line("x"))
        raw["dns"] = {"version": 3, "queries": [{"rrname": "malware.example", "rrtype": "A"}]}
        self.assertEqual(parse_ids_alert(json.dumps(raw)).domain, "malware.example")

    def test_5_1_5_tls_and_http_domains(self):
        """5.1.5 Normal: TLS entrega el SNI; HTTP con una IP como Host no inventa un dominio."""
        self.assertEqual(parse_ids_alert(tls_line("Phishing.Example.NET")).domain, "phishing.example.net")
        self.assertIsNone(parse_ids_alert(REAL_HTTP).domain)
        self.assertIsNone(parse_ids_alert(REAL_TLS).domain)


class ParseInvalidAlerts(unittest.TestCase):
    def test_5_1_6_malformed_lines_are_discarded(self):
        """5.1.6 Invalido: lineas rotas, vacias o incompletas devuelven None y no lanzan excepciones."""
        good = json.loads(alert_line())
        no_src = dict(good); no_src.pop("src_ip")
        bad_ip = dict(good, src_ip="999.1.1.1")
        no_sid = dict(good, alert={"signature": "sin sid", "severity": 1})
        bad_ts = dict(good, timestamp="ayer")
        naive_ts = dict(good, timestamp="2026-11-19T19:00:00")
        cases = [None, "", "   \n", "{rota", "[1, 2, 3]", "null", b"\xff\xfe basura",
                 json.dumps(no_src), json.dumps(bad_ip), json.dumps(no_sid),
                 json.dumps(bad_ts), json.dumps(naive_ts),
                 json.dumps(dict(good, event_type="flow")), json.dumps(dict(good, event_type="stats"))]
        for case in cases:
            with self.subTest(case=str(case)[:40]):
                self.assertIsNone(parse_ids_alert(case))

    def test_5_1_7_out_of_range_values_become_none(self):
        """5.1.7 Limite: una severidad fuera de 1-4 o un puerto invalido no rompen la alerta: quedan en None."""
        a = parse_ids_alert(alert_line(severity=9, dport=70000))
        self.assertIsNone(a.severity)
        self.assertIsNone(a.dest_port)


if __name__ == "__main__":
    unittest.main()
