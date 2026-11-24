"""Motor completo con un Floodlight simulado: de la linea de eve.json a la regla y el incidente."""
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from r5 import Action
from r5.engine import Engine

from .helpers import POLICY, FakeBackend, REAL_TLS, alert_line, dns_answer_line, make_intel, tls_line, ts


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 19, 19, 0, 1, tzinfo=timezone.utc)

    def __call__(self):
        self.now += timedelta(milliseconds=10)
        return self.now


class EngineFlow(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.engine = Engine(POLICY, make_intel(), self.backend, clock=Clock())

    def test_5_8_1_attack_is_blocked_and_logged(self):
        """5.8.1 Funcional: una alerta grave instala los dos drops y deja el incidente con sus tiempos."""
        out = self.engine.process_line(alert_line(severity=1))
        self.assertEqual(out.decision.action, Action.BLOCK)
        self.assertEqual(sorted(self.backend.rules), ["g2-r5-203-0-113-2-in", "g2-r5-203-0-113-2-out"])
        self.assertEqual(out.incident["decision_to_install_ms"], 10.0)

    def test_5_8_2_same_attack_twice_no_duplicates(self):
        """5.8.2 Limite: una segunda alerta de la misma IP (otra peticion) no reinstala reglas pero si se registra."""
        self.engine.process_line(alert_line(severity=1))
        self.engine.clock.now += timedelta(seconds=10)
        out = self.engine.process_line(alert_line(severity=1, when=ts(10), sport=40001))
        self.assertEqual(out.installed, [])
        self.assertEqual(len(self.backend.rules), 2)
        self.assertIsNotNone(out.incident)

    def test_5_8_8_two_sensors_same_packet_counted_once(self):
        """5.8.8 Limite: el mismo paquete visto por los espejos de sw3 y sw5 cuenta una sola vez."""
        first = self.engine.process_line(alert_line(severity=2))
        copy = self.engine.process_line(alert_line(severity=2).replace('"ens6"', '"ens5"'))
        self.assertEqual(first.decision.action, Action.WATCH)
        self.assertTrue(copy.duplicate)
        self.assertEqual(self.engine.stats["duplicates"], 1)

    def test_5_8_9_active_blocks_and_manual_unblock(self):
        """5.8.9 Normal: el bloqueo aparece en la lista activa y el desbloqueo manual quita sus reglas."""
        self.engine.process_line(alert_line(severity=1))
        blocks = self.engine.active_blocks()
        self.assertEqual([b["ip"] for b in blocks], ["203.0.113.2"])
        self.assertEqual(sorted(self.engine.unblock("203.0.113.2")),
                         ["g2-r5-203-0-113-2-in", "g2-r5-203-0-113-2-out"])
        self.assertEqual((self.backend.rules, self.engine.active_blocks()), ({}, []))

    def test_5_8_3_broken_and_benign_lines(self):
        """5.8.3 Invalido / falso positivo: una linea rota y un TLS normal no generan nada."""
        self.assertIsNone(self.engine.process_line("{rota").decision)
        benign = REAL_TLS.replace("192.168.10.10", "93.184.216.34")
        import json
        record = json.loads(benign)
        self.engine.clock = lambda: datetime.fromisoformat(record["timestamp"])
        out = self.engine.process_line(benign)
        self.assertEqual(out.decision.action, Action.IGNORE)
        self.assertIsNone(out.incident)
        self.assertEqual(self.backend.rules, {})

    def test_5_8_4_malicious_domain_blocks_resolved_ip(self):
        """5.8.4 Funcional: una respuesta DNS de un dominio malicioso bloquea la IP resuelta, no el DNS."""
        out = self.engine.process_line(dns_answer_line("www.c2.test", answers=["198.51.100.77"]))
        self.assertEqual(out.decision.action, Action.BLOCK)
        self.assertEqual(out.decision.internal_host, "192.168.10.1")
        self.assertIn("g2-r5-198-51-100-77-in", self.backend.rules)
        self.assertNotIn("g2-r5-8-8-4-4-in", self.backend.rules)

    def test_5_8_5_tls_to_malicious_domain(self):
        """5.8.5 Funcional: un TLS con SNI malicioso bloquea al servidor externo."""
        out = self.engine.process_line(tls_line("login.phishing.example.net", dst="198.51.100.90"))
        self.assertEqual(out.decision.block_ips, ("198.51.100.90",))

    def test_5_8_6_feed_reload_unblocks_removed_ip(self):
        """5.8.6 Limite: si una IP sale del feed, se quitan sus reglas; si sigue, se mantienen."""
        self.engine.process_line(alert_line(src="203.0.113.66", severity=3))
        self.engine.process_line(alert_line(src="198.51.100.23", severity=3))
        self.assertEqual(len(self.backend.rules), 4)
        self.engine.reload_feed("198.51.100.23\nmalware.example\n")
        self.assertEqual(sorted(self.backend.removed), ["g2-r5-203-0-113-66-in", "g2-r5-203-0-113-66-out"])
        self.assertIn("g2-r5-198-51-100-23-in", self.backend.rules)


REAL_DNS_ANSWER = ('{"timestamp":"2026-11-21T20:38:27.356235+0000","flow_id":963921027526507,"in_iface":"ens6",'
                   '"event_type":"dns","src_ip":"192.168.10.1","src_port":58439,"dest_ip":"203.0.113.53",'
                   '"dest_port":53,"proto":"UDP","pkt_src":"gre tunnel","dns":{"version":2,"type":"answer",'
                   '"id":10786,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,'
                   '"rrname":"r1.descarga.malware.example","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":'
                   '"r1.descarga.malware.example","rrtype":"A","ttl":60,"rdata":"203.0.113.70"}],'
                   '"grouped":{"A":["203.0.113.70"]}}}')
REAL_DNS_QUERY = ('{"timestamp":"2026-11-21T20:38:27.355800+0000","flow_id":963921027526507,"in_iface":"ens6",'
                  '"event_type":"dns","src_ip":"192.168.10.1","src_port":58439,"dest_ip":"203.0.113.53",'
                  '"dest_port":53,"proto":"UDP","pkt_src":"gre tunnel","dns":{"type":"query","id":10786,'
                  '"rrname":"r1.descarga.malware.example","rrtype":"A","tx_id":0,"opcode":0}}')


class DnsQueryThenAnswer(unittest.TestCase):
    def test_5_8_10_answer_is_not_a_duplicate_of_its_query(self):
        """5.8.10 Regresion (maqueta 21-nov): la respuesta DNS real no se descarta como duplicado de su consulta."""
        backend = FakeBackend()
        engine = Engine(POLICY, make_intel(), backend, clock=Clock())
        engine.clock = lambda: datetime(2026, 11, 21, 20, 38, 28, tzinfo=timezone.utc)
        query = engine.process_line(REAL_DNS_QUERY)
        answer = engine.process_line(REAL_DNS_ANSWER)
        again = engine.process_line(REAL_DNS_ANSWER.replace('"ens6"', '"ens4"'))  # copia del otro espejo
        self.assertEqual((query.decision.action, query.decision.internal_host), (Action.LOG, "192.168.10.1"))
        self.assertFalse(answer.duplicate)
        self.assertEqual(answer.decision.block_ips, ("203.0.113.70",))
        self.assertIn("g2-r5-203-0-113-70-in", backend.rules)
        self.assertTrue(again.duplicate)


class RecoverAfterRestart(unittest.TestCase):
    def test_5_8_11_blocks_survive_service_restart(self):
        """5.8.11 Regresion (maqueta 21-nov): tras reiniciar, el servicio ve y puede quitar los bloqueos previos."""
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "blocks.json")
            backend = FakeBackend()
            Engine(POLICY, make_intel(), backend, clock=Clock(), state_path=state).process_line(alert_line(severity=1))
            fresh = Engine(POLICY, make_intel(), backend, clock=Clock(), state_path=state)
            self.assertEqual(fresh.active_blocks(), [])
            rules = {name: {"hard_timeout": r["hard_timeout"]} for name, r in backend.rules.items()}
            rules["g2-mt-base-otra-regla"] = {}
            self.assertEqual(fresh.recover_blocks(rules), ["203.0.113.2"])
            self.assertEqual([b["ip"] for b in fresh.active_blocks()], ["203.0.113.2"])
            self.assertEqual(len(fresh.unblock("203.0.113.2")), 2)
            self.assertEqual(backend.rules, {})


class BrokenBackend(FakeBackend):
    def install(self, rule):
        raise ConnectionError("Floodlight no responde")


class EngineFailures(unittest.TestCase):
    def test_5_8_7_floodlight_down_still_logs(self):
        """5.8.7 Contingencia: si Floodlight no responde, el motor no se cae y el incidente queda con el error."""
        engine = Engine(POLICY, make_intel(), BrokenBackend(), clock=Clock())
        out = engine.process_line(alert_line(severity=1))
        self.assertEqual(out.decision.action, Action.BLOCK)
        self.assertEqual(out.installed, [])
        self.assertEqual(len(out.errors), 2)
        self.assertIsNone(out.incident["installed_at"])
        self.assertIn("Floodlight no responde", out.incident["errors"][0])


if __name__ == "__main__":
    unittest.main()
