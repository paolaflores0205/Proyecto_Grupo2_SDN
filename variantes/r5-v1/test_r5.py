import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from r5 import Mitigator, Rejected, SimulatedSwitch, normalize_eve, read_policy


class R5Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.database = Path(self.temp.name) / "audit.sqlite3"
        self.policy = json.loads(Path(__file__).with_name("policy.example.json").read_text())
        self.now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        self.clock = [0.0]
        self.backend = SimulatedSwitch(lambda: self.clock[0])
        self.engine = Mitigator(self.database, self.policy, self.backend)
        self.event = {
            "schema_version": 1, "event_id": "alert-001", "trial_id": self.policy["trial_id"],
            "sensor_id": self.policy["sensor_id"], "source_mode": "synthetic",
            "direction": "request", "event_type": "alert", "timestamp": self.now.isoformat(),
            "src_ip": self.policy["src_ip"], "dest_ip": self.policy["dest_ip"],
            "proto": "TCP", "src_port": 45000, "dest_port": 80,
            "signature_id": 1000001, "signature": "R5_TEST_G2",
        }

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def process(self, **changes):
        return self.engine.process(dict(self.event, **changes), self.now)

    def test_authorized_event_produces_narrow_rule_without_claiming_block(self):
        result = self.process()
        self.assertEqual(result["status"], "SIMULATED_RULE_VERIFIED")
        rule = result["rule"]
        self.assertEqual(rule["ipv4_src"], "192.0.2.10/32")
        self.assertEqual(rule["ipv4_dst"], "192.0.2.20/32")
        self.assertEqual(rule["tcp_dst"], "80")
        self.assertEqual(rule["in_port"], "7")
        self.assertEqual(rule["actions"], "")
        self.assertNotIn("instruction_goto_table", rule)
        self.assertFalse(result["traffic_block_verified"])

    def test_out_of_scope_or_untrusted_context_never_installs(self):
        changes = [
            {"src_ip": "192.0.2.11"}, {"dest_ip": "192.0.2.21"}, {"dest_port": 443},
            {"sensor_id": "other"}, {"trial_id": "other"}, {"source_mode": "live"},
            {"direction": "response"}, {"signature_id": 999}, {"event_type": "flow"},
            {"proto": "ICMP"}, {"src_port": None}, {"src_port": True}, {"dest_port": 0},
            {"src_ip": 3221225994}, {"schema_version": True},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(self.process(**change)["status"], "REJECTED")
        self.assertEqual(self.backend.install_calls, 0)

    def test_missing_fields_and_injected_flow_parameters_are_rejected(self):
        invalid = dict(self.event)
        del invalid["src_port"]
        self.assertEqual(self.engine.process(invalid, self.now)["status"], "REJECTED")
        self.assertEqual(self.process(switch="other", priority=65535)["status"], "REJECTED")
        self.assertEqual(self.backend.install_calls, 0)

    def test_old_future_and_naive_timestamps_rejected(self):
        for stamp in [(self.now-timedelta(seconds=121)).isoformat(),
                      (self.now+timedelta(seconds=6)).isoformat(), "2026-10-22T12:00:00", "bad"]:
            self.assertEqual(self.process(timestamp=stamp)["status"], "REJECTED")
        self.assertEqual(self.backend.install_calls, 0)

    def test_duplicate_does_not_install_again_or_extend_expiry(self):
        first = self.process()
        expiry = self.backend.rules[first["rule"]["name"]][1]
        self.clock[0] = 15
        self.assertEqual(self.process()["status"], "DUPLICATE")
        self.assertEqual(self.backend.install_calls, 1)
        self.assertEqual(self.backend.rules[first["rule"]["name"]][1], expiry)

    def test_duplicate_is_durable_across_process_restart(self):
        self.process()
        self.engine.close()
        self.engine = Mitigator(self.database, self.policy, self.backend)
        self.assertEqual(self.process()["status"], "DUPLICATE")
        self.assertEqual(self.backend.install_calls, 1)

    def test_same_id_with_changed_content_is_rejected(self):
        self.process()
        self.assertEqual(self.process(src_port=45001)["status"], "REJECTED")
        self.assertEqual(self.backend.install_calls, 1)

    def test_install_failure_and_late_failure_never_claim_success(self):
        original = self.backend.install
        def fail(rule):
            original(rule)
            raise TimeoutError("Response lost after simulated installation")
        self.backend.install = fail
        result = self.process()
        self.assertEqual(result["status"], "INSTALL_UNCONFIRMED")
        self.assertFalse(result["traffic_block_verified"])
        self.assertEqual(self.process()["status"], "DUPLICATE")
        self.assertEqual(self.backend.install_calls, 1)
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "SIMULATED_RULE_RETIRED")

    def test_acknowledgement_without_rule_is_not_verified(self):
        self.backend.install = lambda rule: None
        self.assertEqual(self.process()["status"], "VERIFICATION_FAILED")

    def test_different_action_or_scope_is_not_verified(self):
        original = self.backend.install
        def corrupt(rule):
            original(dict(rule, actions="output=1"))
        self.backend.install = corrupt
        self.assertEqual(self.process()["status"], "VERIFICATION_FAILED")

    def test_retirement_preserves_r1_r2_rules(self):
        sentinel = {"name": "g2-mt-grant-existing", "hard_timeout": "30", "actions": "output=3"}
        self.backend.install(sentinel)
        result = self.process()
        retired = self.engine.retire(self.event["event_id"])
        self.assertEqual(retired["status"], "SIMULATED_RULE_RETIRED")
        self.assertFalse(retired["service_recovery_verified"])
        self.assertIsNone(self.backend.observe(result["rule"]["name"]))
        self.assertEqual(self.backend.observe(sentinel["name"]), sentinel)

    def test_unknown_event_cannot_remove_a_rule(self):
        with self.assertRaises(Rejected):
            self.engine.retire("unknown")
        self.assertEqual(self.backend.remove_calls, 0)

    def test_changed_entry_is_not_removed(self):
        result = self.process()
        changed = dict(result["rule"], actions="output=3")
        self.backend.install(changed)
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "REMOVAL_UNCONFIRMED")
        self.assertEqual(self.backend.remove_calls, 0)
        self.assertEqual(self.backend.observe(changed["name"]), changed)

    def test_delete_ack_without_actual_removal_is_not_success(self):
        self.process()
        self.backend.remove = lambda name: None
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "REMOVAL_UNCONFIRMED")

    def test_expiry_and_duplicate_after_expiry_do_not_reinstall(self):
        result = self.process()
        self.clock[0] = 31
        self.assertIsNone(self.backend.observe(result["rule"]["name"]))
        self.assertEqual(self.process()["status"], "DUPLICATE")
        self.assertEqual(self.backend.install_calls, 1)

    def test_duplicate_after_retirement_does_not_reinstall(self):
        self.process()
        self.engine.retire(self.event["event_id"])
        self.assertEqual(self.process()["status"], "DUPLICATE")
        self.assertEqual(self.backend.install_calls, 1)

    def test_invalid_policy_cannot_expand_scope(self):
        for changes in [{"duration_seconds": 0}, {"duration_seconds": 301},
                        {"priority": True}, {"switch_dpid": "bad"},
                        {"schema_version": True}, {"protected_ips": [self.policy["src_ip"]]}]:
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                read_policy(dict(self.policy, **changes))

    def test_eve_normalization_preserves_alert_fields(self):
        eve = {"timestamp": self.event["timestamp"], "event_type": "alert", "flow_id": 123,
               "src_ip": self.event["src_ip"], "dest_ip": self.event["dest_ip"], "proto": "TCP",
               "src_port": 45000, "dest_port": 80,
               "alert": {"signature_id": 1000001, "signature": "R5_TEST_G2"}}
        original = copy.deepcopy(eve)
        event = normalize_eve(eve, event_id="alert-001", trial_id=self.policy["trial_id"],
                              sensor_id=self.policy["sensor_id"], source_mode="synthetic", direction="request")
        self.assertEqual(event, self.event)
        self.assertEqual(eve, original)
        del eve["src_port"]
        event = normalize_eve(eve, event_id="alert-002", trial_id=self.policy["trial_id"],
                              sensor_id=self.policy["sensor_id"], source_mode="synthetic", direction="request")
        self.assertIsNone(event["src_port"])
        self.assertEqual(self.engine.process(event, self.now)["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
