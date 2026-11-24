"""5.15 Plazo original, reinicios, limpieza y fallos parciales del bloqueo."""
import copy
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from r5.block_state import BlockState, RecoveryError
from r5.engine import Engine
from r5.floodlight import FloodlightBackend, FloodlightError
from r5.service import R5Service, build_service, maintenance_loop
from .helpers import POLICY, ROOT, FakeBackend, alert_line, make_intel


IP = '203.0.113.2'


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'blocks.json'
        self.now = datetime(2026, 11, 19, 19, 0, 1, tzinfo=timezone.utc)
        self.backend = FakeBackend()
        self.engine = self.fresh()

    def fresh(self):
        return Engine(POLICY, make_intel(), self.backend, clock=lambda: self.now,
                      state_path=str(self.state))

    def attack(self, engine=None, ip=IP, severity=1):
        return (engine or self.engine).process_line(alert_line(src=ip, severity=severity,
                                                             when=self.now.isoformat()))

    def saved(self):
        return json.loads(self.state.read_text(encoding='utf-8'))['blocks']

    def deadline(self):
        return datetime.fromisoformat(self.engine.blocks[IP]['expires_at'])

    def test_5_15_01_expiry_cleans_pusher_and_state(self):
        self.attack()
        self.now = self.deadline()
        result = self.engine.maintenance()
        self.assertEqual((result['pending'], self.backend.rules, self.saved()), (0, {}, {}))
        self.assertEqual(len(self.backend.removed), 2)

    def test_5_15_02_one_microsecond_before_expiry_is_retained(self):
        self.attack()
        self.now = self.deadline() - timedelta(microseconds=1)
        self.engine.maintenance()
        self.assertEqual(len(self.backend.rules), 2)
        self.assertEqual(self.backend.removed, [])

    def test_5_15_03_restart_preserves_original_deadline(self):
        self.attack()
        original = self.deadline()
        self.now += timedelta(seconds=100)
        fresh = self.fresh()
        recovered = fresh.recover_blocks(copy.deepcopy(self.backend.rules))
        self.assertEqual(recovered, [IP])
        self.assertEqual(datetime.fromisoformat(fresh.blocks[IP]['expires_at']), original)
        self.assertEqual(len(self.backend.rules), 2)  # no POST de recuperacion

    def test_5_15_04_restart_after_expiry_cleans_without_resurrection(self):
        self.attack()
        self.now = self.deadline() + timedelta(seconds=1)
        fresh = self.fresh()
        self.assertEqual(fresh.recover_blocks(copy.deepcopy(self.backend.rules)), [])
        self.assertEqual((self.backend.rules, self.saved()), ({}, {}))

    def test_5_15_05_missing_pusher_entries_are_not_reinstalled(self):
        self.attack()
        self.backend.rules.clear()
        fresh = self.fresh()
        self.assertEqual(fresh.recover_blocks({}), [])
        self.assertEqual(self.saved(), {})

    def test_5_15_06_unknown_own_rule_stops_recovery(self):
        self.backend.rules['g2-r5-203-0-113-2-in'] = {'hard_timeout': '300'}
        before = copy.deepcopy(self.backend.rules)
        with self.assertRaises(RecoveryError):
            self.engine.recover_blocks(copy.deepcopy(self.backend.rules))
        self.assertEqual(self.backend.rules, before)
        self.assertFalse(self.state.exists())

    def test_5_15_07_corrupt_state_is_not_overwritten(self):
        self.state.write_text('{roto', encoding='utf-8')
        with self.assertRaises(RecoveryError):
            self.engine.recover_blocks({})
        self.assertEqual(self.state.read_text(encoding='utf-8'), '{roto')

    def test_5_15_08_different_edge_cannot_reuse_state(self):
        self.attack()
        store = BlockState(self.state, replace(POLICY, edge_port=99))
        with self.assertRaises(RecoveryError):
            store.load()

    def test_5_15_09_failed_delete_is_retried(self):
        self.attack()
        self.now = self.deadline()
        with patch.object(self.backend, 'remove', side_effect=ConnectionError('sin controlador')):
            result = self.engine.maintenance()
        self.assertEqual(result['pending'], 1)
        self.assertEqual(len(result['errors']), 2)
        self.assertEqual(self.saved()[IP]['status'], 'cleanup_pending')
        self.assertEqual(self.engine.maintenance()['pending'], 0)
        self.assertEqual((self.backend.rules, self.saved()), ({}, {}))

    def test_5_15_10_state_failure_prevents_first_post(self):
        with patch.object(self.engine.state_store, 'save', side_effect=OSError('disco lleno')):
            out = self.attack()
        self.assertEqual(self.backend.rules, {})
        self.assertEqual(out.installed, [])
        self.assertTrue(any('No se guardo el plazo' in e for e in out.errors))

    def test_5_15_11_partial_submission_keeps_original_deadline(self):
        original_install = self.backend.install
        def partial(rule):
            if rule['name'].endswith('-out'):
                raise ConnectionError('segundo POST fallo')
            original_install(rule)
        with patch.object(self.backend, 'install', side_effect=partial):
            out = self.attack()
        original = self.deadline()
        self.assertEqual(len(out.installed), 1)
        self.assertEqual(self.saved()[IP]['status'], 'partial')
        self.now += timedelta(seconds=70)
        fresh = self.fresh()
        self.assertEqual(fresh.recover_blocks(copy.deepcopy(self.backend.rules)), [IP])
        out = self.attack(engine=fresh)
        self.assertEqual(len(out.installed), 1)
        missing = self.backend.rules['g2-r5-203-0-113-2-out']
        self.assertEqual(int(missing['hard_timeout']), int((original - self.now).total_seconds()))
        self.assertEqual(datetime.fromisoformat(fresh.blocks[IP]['expires_at']), original)

    def test_5_15_12_crash_between_posts_has_durable_intent(self):
        original_install = self.backend.install
        def crash(rule):
            original_install(rule)
            raise SystemExit('corte simulado')
        with patch.object(self.backend, 'install', side_effect=crash):
            with self.assertRaises(SystemExit):
                self.attack()
        original = self.saved()[IP]['expires_at']
        self.assertEqual(self.saved()[IP]['status'], 'pending')
        self.now += timedelta(seconds=60)
        fresh = self.fresh()
        fresh.recover_blocks(copy.deepcopy(self.backend.rules))
        self.assertEqual(fresh.blocks[IP]['expires_at'], original)

    def test_5_15_13_lost_post_reply_preserves_cleanup_deadline(self):
        original_install = self.backend.install
        def lost_reply(rule):
            original_install(rule)
            raise ConnectionError('respuesta perdida')
        with patch.object(self.backend, 'install', side_effect=lost_reply):
            out = self.attack()
        self.assertEqual(out.installed, [])
        self.assertEqual(len(self.backend.rules), 2)
        self.now = self.deadline()
        self.engine.maintenance()
        self.assertEqual(self.backend.rules, {})

    def test_5_15_14_manual_unblock_is_durable(self):
        self.attack()
        self.assertEqual(len(self.engine.unblock(IP)), 2)
        self.assertEqual(self.saved(), {})
        self.assertEqual(self.fresh().recover_blocks({}), [])

    def test_5_15_15_recovery_restores_feed_origin(self):
        self.attack(ip='203.0.113.66', severity=3)
        fresh = self.fresh()
        fresh.recover_blocks(copy.deepcopy(self.backend.rules))
        self.assertIn('203.0.113.66', fresh.feed_blocks)
        fresh.reload_feed('198.51.100.23\nmalware.example\n')
        self.assertEqual((self.backend.rules, self.saved()), ({}, {}))

    def test_5_15_16_cleanup_leaves_other_modules_untouched(self):
        self.backend.rules.update({'g2-mt-base-1': {}, 'g2-p03-test': {}, 'g2-r50-other': {}})
        self.attack()
        self.now = self.deadline()
        self.engine.maintenance()
        self.assertEqual(set(self.backend.rules), {'g2-mt-base-1', 'g2-p03-test', 'g2-r50-other'})

    def test_5_15_17_forged_rule_name_in_journal_is_rejected(self):
        self.attack()
        raw = json.loads(self.state.read_text(encoding='utf-8'))
        raw['blocks'][IP]['rules'] = ['g2-mt-base-1']
        self.state.write_text(json.dumps(raw), encoding='utf-8')
        with self.assertRaises(RecoveryError):
            self.fresh().recover_blocks(copy.deepcopy(self.backend.rules))
        self.assertEqual(self.backend.removed, [])

    def test_5_15_18_pending_cleanup_does_not_renew_expired_block(self):
        self.attack()
        original = self.deadline()
        self.now = original
        before = copy.deepcopy(self.backend.rules)
        with patch.object(self.backend, 'remove', side_effect=ConnectionError('sin controlador')):
            out = self.attack()
        self.assertEqual(out.installed, [])
        self.assertTrue(any('Limpieza pendiente' in e for e in out.errors))
        self.assertEqual(self.deadline(), original)
        self.assertEqual(self.backend.rules, before)

    def test_5_15_19_new_attack_after_expiry_can_block_again(self):
        self.attack()
        self.now = self.deadline()
        out = self.attack()
        self.assertEqual(len(out.installed), 2)
        self.assertGreater(self.deadline(), self.now)
        self.assertEqual(len(self.backend.removed), 2)

    def test_5_15_20_atomic_replace_failure_preserves_previous_file(self):
        self.attack()
        before = self.state.read_bytes()
        with patch('r5.block_state.os.replace', side_effect=OSError('fallo de reemplazo')):
            with self.assertRaises(OSError):
                self.engine.state_store.save({})
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(list(self.state.parent.glob('.blocks.json-*')), [])

    def test_5_15_21_delete_confirmation_requires_pusher_absence(self):
        backend = FloodlightBackend('http://127.0.0.1:9', POLICY.edge_dpid, POLICY.rule_prefix)
        name = 'g2-r5-203-0-113-2-in'
        with patch.object(backend, '_request', return_value={'status': 'deleted'}):
            with patch.object(backend, 'existing_rule_names', return_value={name}):
                with self.assertRaises(FloodlightError):
                    backend.remove(name)
        with patch.object(backend, '_request') as request:
            with self.assertRaises(FloodlightError):
                backend.remove('g2-mt-base-1')
            request.assert_not_called()

    def test_5_15_26_delete_accepts_existing_tool_prefix_with_trailing_dash(self):
        backend = FloodlightBackend('http://127.0.0.1:9', POLICY.edge_dpid, 'g2-r5e5-')
        with patch.object(backend, '_request') as request:
            with patch.object(backend, 'existing_rule_names', return_value=set()):
                backend.remove('g2-r5e5-ip-ida-sw5')
        request.assert_called_once()

    def test_5_15_22_service_build_uses_persistence_and_valid_default_retention(self):
        config = {'policy': str(ROOT / 'config/policy.json'),
                  'incident_log': str(self.state.parent / 'incidents.jsonl')}
        fake = Mock()
        fake.list_rules.return_value = {}
        with patch('r5.service.FloodlightBackend', return_value=fake):
            service = build_service(config)
        self.assertEqual(service.engine.dedupe_seconds, 125)
        self.assertEqual(service.engine.state_store.path, self.state.parent / 'r5-block-state.json')
        fake.install.assert_not_called()

    def test_5_15_23_service_does_not_start_with_unverifiable_deadline(self):
        config = {'policy': str(ROOT / 'config/policy.json'), 'block_state': str(self.state),
                  'incident_log': str(self.state.parent / 'incidents.jsonl')}
        fake = Mock()
        fake.list_rules.return_value = {'g2-r5-203-0-113-2-in': {}}
        with patch('r5.service.FloodlightBackend', return_value=fake):
            with self.assertRaises(RecoveryError):
                build_service(config)
        fake.install.assert_not_called()
        fake.remove.assert_not_called()

    def test_5_15_24_maintenance_runs_without_incoming_events(self):
        self.attack()
        self.now = self.deadline()
        service = R5Service(self.engine, None, None)
        stop = threading.Event()
        original = service.maintenance_once
        def one_tick():
            try:
                return original()
            finally:
                stop.set()
        with patch.object(service, 'maintenance_once', side_effect=one_tick):
            worker = threading.Thread(target=maintenance_loop, args=(service, stop))
            worker.start()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual((self.backend.rules, self.saved()), ({}, {}))

    def test_5_15_25_maintenance_error_is_reported(self):
        stop = threading.Event()
        service = Mock()
        def failed():
            stop.set()
            raise OSError('fallo simulado')
        service.maintenance_once.side_effect = failed
        captured = io.StringIO()
        with redirect_stdout(captured):
            maintenance_loop(service, stop)
        self.assertIn('error_mantenimiento', captured.getvalue())
        self.assertIn('fallo simulado', captured.getvalue())


if __name__ == '__main__':
    unittest.main()
