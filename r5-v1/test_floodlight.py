"""API ficticia en memoria: nunca abre un socket ni usa el VNRT."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from floodlight import FloodlightSwitch, IntegrationError, LocalHTTP, matches_drop
from r5 import Mitigator, build_rule, read_policy


def actual(rule, **changes):
    keys = {"in_port", "eth_type", "ip_proto", "ipv4_src", "ipv4_dst", "tcp_dst", "udp_dst"}
    row = {"tableId": "0x0", "priority": rule["priority"],
           "match": {k: v for k, v in rule.items() if k in keys},
           "instructions": {}, "hardTimeoutSec": int(rule["hard_timeout"]), "idleTimeoutSec": 0}
    return dict(row, **changes)


class FakeAPI:
    def __init__(self, dpid):
        self.dpid, self.entries, self.flows, self.calls = dpid, {}, [], []
        self.install_actual = True
        self.fail_after_post = False
        self.delete_actual = True

    def __call__(self, path, method="GET", data=None):
        self.calls.append((path, method, data))
        if path == "/wm/core/controller/switches/json":
            return [{"switchDPID": self.dpid}]
        if path == "/wm/staticflowpusher/list/all/json":
            return {self.dpid: [{name: fields} for name, fields in self.entries.items()]}
        if path.endswith("/flow/json"):
            return {self.dpid: {"flows": self.flows}}
        if path == "/wm/staticflowpusher/json" and method == "POST":
            self.entries[data["name"]] = dict(data)
            if self.install_actual:
                self.flows.append(actual(data))
            if self.fail_after_post:
                raise TimeoutError("Respuesta perdida")
            return {"status": "Entry pushed"}
        if path == "/wm/staticflowpusher/json" and method == "DELETE":
            rule = self.entries.pop(data["name"], None)
            if rule and self.delete_actual:
                self.flows = [r for r in self.flows if not matches_drop(rule, r)]
            return {"status": "Entry deleted"}
        raise AssertionError((path, method))


class FloodlightTests(unittest.TestCase):
    def setUp(self):
        self.policy = read_policy(json.loads(Path(__file__).with_name("policy.example.json").read_text()))
        self.event = {"schema_version": 1, "event_id": "alert-api-1", "trial_id": self.policy["trial_id"],
                      "sensor_id": self.policy["sensor_id"], "source_mode": "synthetic", "direction": "request",
                      "event_type": "alert", "timestamp": datetime.now(timezone.utc).isoformat(),
                      "src_ip": self.policy["src_ip"], "dest_ip": self.policy["dest_ip"], "proto": "TCP",
                      "src_port": 45000, "dest_port": 80, "signature_id": 1000001, "signature": "R5_TEST_G2"}
        self.rule = build_rule(self.event, self.policy)
        self.api = FakeAPI(self.policy["switch_dpid"])
        self.backend = FloodlightSwitch(self.api.dpid, enable_writes=True, request=self.api,
                                        verification_timeout=0, poll_interval=0)
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.database = Path(self.temp.name) / "audit.sqlite3"
        self.engine = Mitigator(self.database, self.policy, self.backend)

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_preflight_never_writes(self):
        self.backend.preflight(self.rule)
        self.assertTrue(all(method == "GET" for _, method, _ in self.api.calls))

    def test_real_adapter_uses_pusher_and_actual_flow_stats(self):
        result = self.engine.process(self.event)
        self.assertEqual(result["status"], "RULE_VERIFIED_TRAFFIC_PENDING")
        self.assertFalse(result["simulation"])
        self.assertFalse(result["traffic_block_verified"])
        self.assertTrue(any(method == "POST" for _, method, _ in self.api.calls))
        self.assertTrue(any(path.endswith("/flow/json") for path, _, _ in self.api.calls))

    def test_http_success_alone_does_not_verify_rule(self):
        self.api.install_actual = False
        self.assertEqual(self.engine.process(self.event)["status"], "VERIFICATION_FAILED")

    def test_inspected_floodlight_drop_serialization(self):
        row = actual(self.rule, instructions={"none": "drop"})
        self.assertTrue(matches_drop(self.rule, row))
        self.assertFalse(matches_drop(self.rule, dict(row, instructions={"none": "output=1"})))
        self.backend.track(self.rule)
        self.api.entries[self.rule["name"]] = dict(row)
        del self.api.entries[self.rule["name"]]["tableId"]
        self.api.flows = [row]
        # La API falsa elimina la definición; imitar el retiro del dataplane después.
        original = self.api.__class__.__call__
        def request(path, method="GET", data=None):
            if method == "DELETE":
                self.api.entries.pop(data["name"], None)
                self.api.flows.clear()
                return {"status": "Entry deleted"}
            return original(self.api, path, method, data)
        self.backend.request = request
        self.backend.remove(self.rule["name"])
        self.assertNotIn(self.rule["name"], self.api.entries)

    def test_retirement_removes_only_recorded_name(self):
        self.api.entries["g2-mt-base-default"] = {"actions": "drop"}
        self.engine.process(self.event)
        result = self.engine.retire(self.event["event_id"])
        self.assertEqual(result["status"], "RULE_RETIRED_RECOVERY_PENDING")
        self.assertFalse(result["service_recovery_verified"])
        deleted = [data for _, method, data in self.api.calls if method == "DELETE"]
        self.assertEqual(deleted, [{"name": self.rule["name"]}])
        self.assertIn("g2-mt-base-default", self.api.entries)

    def test_restart_then_retire_uses_durable_ownership(self):
        self.engine.process(self.event)
        self.engine.close()
        self.backend = FloodlightSwitch(self.api.dpid, enable_writes=True, request=self.api, verification_timeout=0)
        self.engine = Mitigator(self.database, self.policy, self.backend)
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "RULE_RETIRED_RECOVERY_PENDING")

    def test_expired_rule_still_removed_from_pusher(self):
        self.engine.process(self.event)
        self.api.flows.clear()
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "RULE_RETIRED_RECOVERY_PENDING")
        self.assertNotIn(self.rule["name"], self.api.entries)

    def test_lost_post_reply_and_duplicate_do_not_reinstall(self):
        self.api.fail_after_post = True
        self.assertEqual(self.engine.process(self.event)["status"], "INSTALL_UNCONFIRMED")
        self.assertEqual(self.engine.process(self.event)["status"], "DUPLICATE")
        self.assertEqual(sum(method == "POST" for _, method, _ in self.api.calls), 1)
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "RULE_RETIRED_RECOVERY_PENDING")

    def test_higher_priority_overlap_prevents_install(self):
        self.api.flows = [{"tableId": 0, "priority": 3000, "match": {"eth_type": "0x0800"}}]
        with self.assertRaises(IntegrationError):
            self.backend.install(self.rule)
        self.assertFalse(any(method == "POST" for _, method, _ in self.api.calls))

    def test_high_priority_discovery_does_not_conflict_with_ipv4(self):
        self.api.flows = [{"tableId": 0, "priority": 64000, "match": {"eth_type": "0x88cc"}}]
        self.backend.install(self.rule)
        self.assertTrue(any(method == "POST" for _, method, _ in self.api.calls))

    def test_existing_name_is_not_overwritten(self):
        self.api.entries[self.rule["name"]] = dict(self.rule)
        with self.assertRaises(IntegrationError):
            self.backend.install(self.rule)
        self.assertFalse(any(method == "POST" for _, method, _ in self.api.calls))

    def test_changed_pusher_entry_is_not_deleted(self):
        self.engine.process(self.event)
        self.api.entries[self.rule["name"]]["actions"] = "output=1"
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "REMOVAL_UNCONFIRMED")
        self.assertFalse(any(method == "DELETE" for _, method, _ in self.api.calls))

    def test_changed_actual_entry_is_not_deleted(self):
        self.engine.process(self.event)
        self.api.flows[0]["instructions"] = {"instruction_goto_table": {"instruction_goto_table": 10}}
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "REMOVAL_UNCONFIRMED")
        self.assertFalse(any(method == "DELETE" for _, method, _ in self.api.calls))

    def test_delete_ack_without_actual_removal_is_not_confirmed(self):
        self.engine.process(self.event)
        self.api.delete_actual = False
        self.assertEqual(self.engine.retire(self.event["event_id"])["status"], "REMOVAL_UNCONFIRMED")

    def test_disabled_writes_cannot_mutate(self):
        self.backend.enable_writes = False
        with self.assertRaises(IntegrationError):
            self.backend.install(self.rule)
        with self.assertRaises(IntegrationError):
            self.backend.remove(self.rule["name"])
        self.assertEqual(self.api.calls, [])

    def test_unknown_or_foreign_rule_cannot_be_removed(self):
        with self.assertRaises(IntegrationError):
            self.backend.remove("g2-mt-base-default")
        with self.assertRaises(IntegrationError):
            self.backend.track(dict(self.rule, name="g2-mt-base-default"))
        with self.assertRaises(IntegrationError):
            self.backend.track(dict(self.rule, switch="00:00:00:00:00:00:00:02"))
        self.assertEqual(self.api.calls, [])

    def test_http_transport_uses_no_redirects_or_proxies(self):
        with patch("floodlight.http.client.HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"status":"Entry pushed"}'
            self.assertEqual(LocalHTTP()("/wm/staticflowpusher/json", "POST", self.rule)["status"], "Entry pushed")
            self.assertEqual(connection.return_value.request.call_args.args[:2], ("POST", "/wm/staticflowpusher/json"))
            connection.return_value.close.assert_called_once()
        for url in ["http://10.20.12.34:8080", "http://user:password@127.0.0.1:8080", "http://127.0.0.1:8080/path"]:
            with self.assertRaises(IntegrationError):
                LocalHTTP(url)


if __name__ == "__main__":
    unittest.main()
