from copy import deepcopy
import unittest

from coherencia import compare_snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.drop = {
            "dpid": "00:00:00:00:00:00:00:02", "table": 20, "priority": 550,
            "match": {"metadata": "0x105/0xff", "ipv4_dst": "192.0.2.1", "eth_type": "0x0800"},
            "actions": [], "idle_timeout": 0, "hard_timeout": 30,
        }
        self.permit = {
            **self.drop,
            "priority": 501,
            "match": {**self.drop["match"], "ipv4_dst": "192.0.2.0/24"},
            "actions": ["goto_table:30"],
        }
        self.state = {"revision": 12, "generations": [0, 1]}
        self.expected = {**self.state, "rules": [self.drop, self.permit], "drop_checks": [0]}
        self.observed = {
            "complete": True, "before": deepcopy(self.state), "after": deepcopy(self.state),
            "rules": deepcopy(self.expected["rules"]),
        }

    def compare(self):
        return compare_snapshot(self.expected, self.observed)

    def test_equivalent_spellings_and_valid_renewal(self):
        self.observed["rules"][0].update(dpid="0x2", actions=["drop"])
        self.observed["rules"][0]["match"].update(metadata="5/255", ipv4_dst="192.0.2.1/32")
        self.observed["after"]["generations"] = [1, 0]
        self.assertEqual(self.compare()["status"], "coherente")

    def test_missing_rule(self):
        self.observed["rules"].pop()
        self.assertEqual(len(self.compare()["missing"]), 1)
        self.assertEqual(self.compare()["status"], "inconsistente")

    def test_changed_rule_fields(self):
        variations = (
            {"table": 10},
            {"dpid": 3},
            {"actions": ["output:1"]},
            {"hard_timeout": 0},
            {"match": {**self.drop["match"], "ipv4_dst": "192.0.2.2"}},
            {"match": {**self.drop["match"], "metadata": "0x05/0x0f"}},
        )
        for change in variations:
            with self.subTest(change=change):
                self.observed["rules"][0] = {**self.drop, **change}
                result = self.compare()
                self.assertEqual(len(result["missing"]), 1)
                self.assertEqual(len(result["unexpected"]), 1)

    def test_drop_priority_and_tied_permit(self):
        self.assertEqual(self.compare()["drop_conflicts"], [])
        for priority in (550, 551):
            with self.subTest(priority=priority):
                self.observed["rules"][1]["priority"] = priority
                self.assertEqual(len(self.compare()["drop_conflicts"]), 1)

    def test_nonoverlapping_metadata_and_other_table(self):
        self.observed["rules"][1]["match"]["metadata"] = "0x06/0xff"
        self.observed["rules"][1]["priority"] = 551
        self.assertEqual(self.compare()["drop_conflicts"], [])
        self.observed["rules"][1]["match"]["metadata"] = "0x05/0xff"
        self.observed["rules"][1]["table"] = 30
        self.assertEqual(self.compare()["drop_conflicts"], [])

    def test_revision_or_generation_changes_midcapture(self):
        for change in ({"revision": 13}, {"generations": [1]}):
            with self.subTest(change=change):
                self.observed["after"] = {**self.state, **change}
                self.observed["rules"].clear()
                self.assertEqual(self.compare()["status"], "transitorio")

    def test_logout_with_matching_revision_and_removed_rules(self):
        state = {"revision": 13, "generations": []}
        self.expected = {**state, "rules": []}
        self.observed.update(before=state, after=state, rules=[])
        self.assertEqual(self.compare()["status"], "coherente")

    def test_incomplete_capture_or_stale_reference(self):
        self.observed["complete"] = False
        self.assertEqual(self.compare()["status"], "no_verificable")
        self.observed["complete"] = True
        self.expected["revision"] = 11
        self.assertEqual(self.compare()["status"], "no_verificable")

    def test_unsupported_match_is_reported_as_invalid_input(self):
        self.observed["rules"][0]["match"]["unrecognized"] = 10
        with self.assertRaisesRegex(ValueError, "sin normalizar"):
            self.compare()


if __name__ == "__main__":
    unittest.main()
