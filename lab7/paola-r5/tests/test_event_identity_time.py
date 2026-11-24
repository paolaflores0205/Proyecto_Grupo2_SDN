"""5.16 Identidad de registros, repeticion real y validez temporal de eventos."""
import json
import unittest
from datetime import datetime, timedelta, timezone

from r5.alerts import parse_ids_alert
from r5.engine import Engine
from r5.model import Action
from r5.policy import load_policy, PolicyError
from r5.service import R5Service
from .helpers import POLICY, ROOT, FakeBackend, alert_line, make_intel


class EventSafety(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 19, 19, 0, 1, tzinfo=timezone.utc)
        self.backend = FakeBackend()
        self.engine = Engine(POLICY, make_intel(), self.backend, clock=lambda: self.now)

    def line(self, offset=0, **changes):
        raw = json.loads(alert_line(severity=2))
        raw['timestamp'] = (self.now + timedelta(seconds=offset)).isoformat()
        raw.update(changes)
        return json.dumps(raw)

    def test_5_16_01_mirror_and_json_order(self):
        first = self.line()
        raw = json.loads(first)
        raw.update(in_iface='ens5', pcap_cnt=314, pkt_src='gre tunnel')
        self.engine.process_line(first)
        out = self.engine.process_line(json.dumps(raw, sort_keys=True, indent=2))
        self.assertTrue(out.duplicate)
        self.assertEqual(self.engine.stats['incidents'], 1)

    def test_5_16_02_different_times_same_flow_reach_threshold(self):
        outs = [self.engine.process_line(self.line(offset=x)) for x in (-0.2, -0.1, 0)]
        self.assertEqual([o.decision.action for o in outs], [Action.WATCH, Action.WATCH, Action.BLOCK])
        self.assertEqual(len(self.backend.rules), 2)

    def test_5_16_03_different_transactions_are_preserved(self):
        outs = [self.engine.process_line(self.line(tx_id=i)) for i in range(3)]
        self.assertEqual([o.duplicate for o in outs], [False, False, False])
        self.assertEqual(outs[-1].decision.action, Action.BLOCK)

    def test_5_16_04_different_flow_is_preserved(self):
        self.engine.process_line(self.line(flow_id=1))
        self.assertFalse(self.engine.process_line(self.line(flow_id=2)).duplicate)

    def test_5_16_05_different_http_paths_are_preserved(self):
        self.engine.process_line(self.line(http={'hostname': 'normal.test', 'url': '/uno'}))
        out = self.engine.process_line(self.line(http={'hostname': 'normal.test', 'url': '/dos'}))
        self.assertFalse(out.duplicate)

    def test_5_16_06_signature_is_part_of_identity(self):
        first = json.loads(self.line())
        self.engine.process_line(json.dumps(first))
        first['alert']['signature_id'] += 1
        self.assertFalse(self.engine.process_line(json.dumps(first)).duplicate)

    def test_5_16_07_repeats_never_reach_watch_threshold(self):
        line = self.line()
        for _ in range(10):
            self.engine.process_line(line)
        self.assertEqual(self.engine.stats['duplicates'], 9)
        self.assertEqual(self.backend.rules, {})
        self.assertEqual(self.engine.stats['incidents'], 1)

    def test_5_16_08_replay_after_old_two_second_window(self):
        line = self.line()
        self.engine.process_line(line)
        self.now += timedelta(seconds=3)
        self.assertTrue(self.engine.process_line(line).duplicate)

    def test_5_16_09_stale_does_not_change_rules_or_tracker(self):
        out = self.engine.process_line(self.line(offset=-120.000001))
        self.assertEqual(out.rejected, 'stale')
        self.assertEqual((out.incident, out.decision, self.backend.rules), (None, None, {}))
        self.assertEqual(self.engine.tracker.tracked_ips(), 0)
        self.assertEqual(len(self.engine._seen), 0)
        self.assertEqual(self.engine.stats['rejected_stale'], 1)

    def test_5_16_10_exact_age_boundary_is_accepted(self):
        self.assertIsNone(self.engine.process_line(self.line(offset=-120)).rejected)
        self.assertEqual(self.engine.stats['incidents'], 1)

    def test_5_16_11_future_is_rejected_without_side_effects(self):
        out = self.engine.process_line(self.line(offset=5.000001))
        self.assertEqual(out.rejected, 'future')
        self.assertEqual((self.engine.tracker.tracked_ips(), len(self.engine._seen)), (0, 0))
        self.assertEqual(self.backend.rules, {})
        self.assertEqual(self.engine.stats['last_rejection']['reason'], 'future')

    def test_5_16_12_exact_future_boundary_is_accepted(self):
        self.assertIsNone(self.engine.process_line(self.line(offset=5)).rejected)
        self.assertEqual(self.engine.stats['incidents'], 1)

    def test_5_16_13_old_replay_is_stale_before_deduplication(self):
        line = self.line()
        self.engine.process_line(line)
        self.now += timedelta(seconds=121)
        out = self.engine.process_line(line)
        self.assertEqual(out.rejected, 'stale')
        self.assertFalse(out.duplicate)

    def test_5_16_14_same_instant_other_timezone_is_duplicate(self):
        line = self.line()
        self.engine.process_line(line)
        raw = json.loads(line)
        raw['timestamp'] = self.now.astimezone(timezone(timedelta(hours=-5))).isoformat()
        self.assertTrue(self.engine.process_line(json.dumps(raw)).duplicate)

    def test_5_16_15_rejected_event_does_not_poison_dedupe(self):
        line = self.line(offset=6)
        self.assertEqual(self.engine.process_line(line).rejected, 'future')
        self.now += timedelta(seconds=2)
        out = self.engine.process_line(line)
        self.assertIsNone(out.rejected)
        self.assertFalse(out.duplicate)

    def test_5_16_16_service_reports_rejections_and_duplicates(self):
        service = R5Service(self.engine, None, None)
        good = self.line()
        out = service.handle_lines([good, good, self.line(-121), self.line(6)])
        self.assertEqual(out['rejected'], {'stale': 1, 'future': 1})
        self.assertEqual((out['processed'], out['duplicates']), (4, 1))

    def test_5_16_17_dedupe_uses_monotonic_time(self):
        elapsed = [0.0]
        engine = Engine(POLICY, make_intel(), self.backend, clock=lambda: self.now,
                        monotonic_clock=lambda: elapsed[0])
        line = self.line()
        engine.process_line(line)
        elapsed[0] = 3
        self.now -= timedelta(seconds=1)  # pequeno ajuste del reloj de sistema
        self.assertTrue(engine.process_line(line).duplicate)

    def test_5_16_18_cache_expiry_is_not_renewed_by_replays(self):
        elapsed = [0.0]
        engine = Engine(POLICY, make_intel(), self.backend, clock=lambda: self.now,
                        monotonic_clock=lambda: elapsed[0])
        line = self.line()
        engine.process_line(line)
        elapsed[0] = 100
        engine.process_line(line)
        self.assertEqual(next(iter(engine._seen.values())), 0)
        elapsed[0] = 126
        self.now += timedelta(seconds=126)
        engine.process_line(self.line())
        self.assertEqual(len(engine._seen), 1)

    def test_5_16_19_policy_rejects_invalid_windows(self):
        base = json.loads((ROOT / 'config/policy.json').read_text(encoding='utf-8'))
        for field, value in [('max_age_seconds', 0), ('max_age_seconds', True),
                             ('max_future_skew_seconds', -1), ('max_future_skew_seconds', 61)]:
            with self.subTest(field=field, value=value):
                raw = dict(base, events={field: value})
                with self.assertRaises(PolicyError):
                    load_policy(raw)
        with self.assertRaises(PolicyError):
            load_policy(dict(base, events=[]))

    def test_5_16_20_policy_defaults_are_enabled(self):
        raw = json.loads((ROOT / 'config/policy.json').read_text(encoding='utf-8'))
        raw.pop('events', None)
        policy = load_policy(raw)
        self.assertEqual((policy.max_event_age_seconds, policy.max_future_skew_seconds), (120, 5))
        with self.assertRaises(ValueError):
            Engine(policy, make_intel(), self.backend, dedupe_seconds=2)

    def test_5_16_21_dns_query_answer_at_same_time_are_distinct(self):
        common = json.loads(self.line(event_type='dns'))
        common.pop('alert')
        common['dns'] = {'type': 'query', 'rrname': 'malware.example', 'id': 7}
        a = parse_ids_alert(json.dumps(common))
        common['dns'] = {'type': 'answer', 'rrname': 'malware.example', 'id': 7,
                         'answers': [{'rrtype': 'A', 'rdata': '203.0.113.77'}]}
        b = parse_ids_alert(json.dumps(common))
        self.assertNotEqual(a.event_id, b.event_id)
        self.assertNotEqual(a.resolved_ips, b.resolved_ips)

    def test_5_16_22_retention_includes_exact_validity_boundary(self):
        elapsed = [0.0]
        engine = Engine(POLICY, make_intel(), self.backend, clock=lambda: self.now,
                        monotonic_clock=lambda: elapsed[0])
        line = self.line(offset=5)
        engine.process_line(line)
        elapsed[0] = 125
        self.now += timedelta(seconds=125)
        out = engine.process_line(line)  # edad exacta de 120 s: sigue siendo valido
        self.assertIsNone(out.rejected)
        self.assertTrue(out.duplicate)


if __name__ == '__main__':
    unittest.main()
