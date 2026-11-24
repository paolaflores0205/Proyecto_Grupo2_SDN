"""5.14 Blindaje: que un atacante no pueda usar a R5 contra la propia red.

Escenarios de abuso: IPs falsificadas sin fin para llenar el switch o la memoria, una respuesta
DNS con decenas de IPs, un feed envenenado con una red enorme y politicas con limites absurdos.
"""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from r5 import Action, FeedRejected, PolicyError, ThreatIntel, load_policy
from r5.engine import Engine
from r5.service import R5Service

from .helpers import POLICY, ROOT, FakeBackend, alert_line, dns_answer_line, make_intel
from .test_engine import BrokenBackend, Clock


def attacker(i: int) -> str:
    return f"198.18.{i // 250}.{i % 250 + 1}"  # rango de pruebas, nunca enrutable


class ActiveBlockCap(unittest.TestCase):
    def test_5_14_1_cap_keeps_existing_blocks(self):
        """5.14.1 Limite: al llegar al tope de IPs bloqueadas, las nuevas no se bloquean y las viejas siguen."""
        backend = FakeBackend()
        engine = Engine(replace(POLICY, max_active_blocks=3), make_intel(), backend, clock=Clock())
        outs = [engine.process_line(alert_line(src=attacker(i), severity=1)) for i in range(5)]
        self.assertEqual([len(o.installed) for o in outs], [2, 2, 2, 0, 0])
        self.assertEqual(outs[3].throttled, [attacker(3)])
        self.assertEqual(len(backend.rules), 6)
        self.assertIn("tope de 3 IPs", outs[3].incident["brake"])
        self.assertEqual(outs[3].incident["blocked_ips"], [])
        self.assertEqual(engine.stats["throttled"], 2)
        # una IP que ya esta bloqueada no necesita un bloqueo nuevo: el freno no la toca
        again = engine.process_line(alert_line(src=attacker(0), severity=1, sport=40999))
        self.assertEqual((again.throttled, again.decision.action), ([], Action.BLOCK))
        self.assertTrue(engine.brake_status()["engaged"])

    def test_5_14_2_unblock_frees_a_slot(self):
        """5.14.2 Normal: al desbloquear una IP se libera su cupo y la siguiente si se bloquea."""
        engine = Engine(replace(POLICY, max_active_blocks=1), make_intel(), FakeBackend(), clock=Clock())
        engine.process_line(alert_line(src=attacker(0), severity=1))
        self.assertEqual(engine.process_line(alert_line(src=attacker(1), severity=1)).throttled, [attacker(1)])
        engine.unblock(attacker(0))
        self.assertEqual(len(engine.process_line(alert_line(src=attacker(1), severity=1, sport=41000)).installed), 2)


class NewBlocksPerMinute(unittest.TestCase):
    def test_5_14_3_rate_limit_and_recovery(self):
        """5.14.3 Limite: mas de N bloqueos nuevos en un minuto se frenan; pasado el minuto se vuelve a bloquear."""
        clock = Clock()
        engine = Engine(replace(POLICY, max_new_blocks_per_minute=2), make_intel(), FakeBackend(), clock=clock)
        outs = [engine.process_line(alert_line(src=attacker(i), severity=1)) for i in range(3)]
        self.assertEqual([o.throttled for o in outs], [[], [], [attacker(2)]])
        self.assertIn("2 bloqueos nuevos por minuto", outs[2].incident["brake"])
        clock.now += timedelta(seconds=61)
        late = engine.process_line(alert_line(src=attacker(3), severity=1))
        self.assertEqual((late.throttled, len(late.installed)), ([], 2))


class IpsPerDecision(unittest.TestCase):
    def test_5_14_4_dns_answer_with_many_ips(self):
        """5.14.4 Limite: una respuesta DNS maliciosa con 20 IPs solo bloquea las primeras 8."""
        backend = FakeBackend()
        engine = Engine(POLICY, make_intel(), backend, clock=Clock())
        ips = [f"198.51.100.{i}" for i in range(100, 120)]
        out = engine.process_line(dns_answer_line("cdn.c2.test", answers=ips))
        self.assertEqual(out.decision.action, Action.BLOCK)
        self.assertEqual(len(backend.rules), 16)
        self.assertEqual(out.throttled, ips[8:])
        self.assertEqual(out.incident["blocked_ips"], ips[:8])
        self.assertIn("maximo de 8 IPs por decision (20 pedidas)", out.incident["brake"])


class PoisonedFeed(unittest.TestCase):
    def test_5_14_5_too_broad_networks_rejected(self):
        """5.14.5 Invalido: un feed con 0.0.0.0/0 o 10.0.0.0/8 no puede bloquear medio Internet."""
        intel = ThreatIntel(POLICY.whitelist)
        report = intel.update_blacklist("0.0.0.0/0\n10.0.0.0/8\n2001:db8::/16\n203.0.113.0/24\n")
        self.assertEqual(report.added_networks, ["203.0.113.0/24"])
        self.assertEqual([t for _, t, _ in report.ignored], ["0.0.0.0/0", "10.0.0.0/8", "2001:db8::/16"])
        self.assertIn("demasiado amplia (/0)", report.ignored[0][2])
        self.assertFalse(intel.is_malicious_ip("93.184.216.34"))
        with self.assertRaises(FeedRejected):  # feed solo con redes enormes: se conserva el anterior
            intel.update_blacklist("0.0.0.0/1\n128.0.0.0/1\n")
        self.assertTrue(intel.is_malicious_ip("203.0.113.9"))

    def test_5_14_6_engine_reload_uses_same_check(self):
        """5.14.6 Invalido: la recarga del feed desde la API tambien rechaza redes enormes."""
        engine = Engine(POLICY, make_intel(), FakeBackend(), clock=Clock())
        report = engine.reload_feed("0.0.0.0/0\nmalware.example\n")
        self.assertEqual([t for _, t, _ in report.ignored], ["0.0.0.0/0"])
        self.assertFalse(engine.intel.is_malicious_ip("93.184.216.34"))


class BoundedMemory(unittest.TestCase):
    def test_5_14_7_tracker_forgets_oldest(self):
        """5.14.7 Limite: miles de IPs falsificadas no hacen crecer sin fin la memoria de reincidencias."""
        engine = Engine(replace(POLICY, max_tracked_ips=100), make_intel(), FakeBackend(), clock=Clock())
        for i in range(1000):
            engine.process_line(alert_line(src=attacker(i), severity=2))
        self.assertEqual(engine.tracker.tracked_ips(), 100)
        self.assertEqual(engine.brake_status()["tracked_ips"], 100)


class IncidentFile(unittest.TestCase):
    def test_5_14_8_errors_and_brakes_reach_the_file(self):
        """5.14.8 Regresion: los errores y los frenos quedan escritos en incidents.jsonl, no solo en memoria."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incidents.jsonl"
            Engine(POLICY, make_intel(), BrokenBackend(), incident_path=str(path),
                   clock=Clock()).process_line(alert_line(severity=1))
            capped = Engine(replace(POLICY, max_active_blocks=1), make_intel(), FakeBackend(),
                            incident_path=str(path), clock=Clock())
            capped.process_line(alert_line(src=attacker(0), severity=1))
            capped.process_line(alert_line(src=attacker(1), severity=1))
            records = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
        self.assertIn("Floodlight no responde", records[0]["errors"][0])
        self.assertEqual(records[1]["errors"], [])
        self.assertEqual(records[2]["throttled_ips"], [attacker(1)])
        self.assertIn("tope de 1 IPs", records[2]["brake"])


class LimitsInPolicy(unittest.TestCase):
    def test_5_14_9_defaults_and_validation(self):
        """5.14.9 Invalido: la seccion limits es opcional, pero con valores absurdos el modulo no arranca."""
        raw = json.loads((ROOT / "config" / "policy.json").read_text(encoding="utf-8"))
        raw.pop("limits", None)
        p = load_policy(raw)
        self.assertEqual((p.max_active_blocks, p.max_new_blocks_per_minute, p.max_ips_per_decision,
                          p.feed_min_prefix_v4), (500, 30, 8, 16))
        for key, value in {"max_active_blocks": 0, "max_new_blocks_per_minute": "30",
                           "max_ips_per_decision": 100, "max_tracked_ips": 5, "feed_min_prefix_v4": 33}.items():
            bad = dict(raw, limits={key: value})
            with self.subTest(limite=key):
                with self.assertRaises(PolicyError):
                    load_policy(bad)
        with self.assertRaises(PolicyError):
            load_policy(dict(raw, limits=[500]))

    def test_5_14_10_health_shows_brakes(self):
        """5.14.10 Normal: /r5/health muestra cuantos bloqueos hay, los limites y si un freno esta activo."""
        engine = Engine(replace(POLICY, max_active_blocks=1), make_intel(), FakeBackend(), clock=Clock())
        service = R5Service(engine, None, None)
        journal = io.StringIO()
        with redirect_stdout(journal):
            result = service.handle_lines([alert_line(src=attacker(0), severity=1),
                                           alert_line(src=attacker(1), severity=1)])
        self.assertIn('"status": "freno_activado"', journal.getvalue())
        self.assertEqual(result["throttled"], [attacker(1)])
        brakes = service.health()["brakes"]
        self.assertEqual((brakes["active_blocks"], brakes["max_active_blocks"], brakes["engaged"]), (1, 1, True))
        self.assertEqual(brakes["last"]["ips"], [attacker(1)])


if __name__ == "__main__":
    unittest.main()
