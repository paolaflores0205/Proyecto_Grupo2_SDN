"""Unit tests for sdn_r4.R4Engine (offline, deterministic)."""
import unittest
from sdn_r4 import R4Engine


TOPOLOGY = {
    "clients": ["h1", "h2", "h3"],
    "nodes": {
        "h1": {"switch": "sw2", "port": 3, "mac": "fa:16:3e:53:96:3e", "ip": "192.168.10.1"},
        "h2": {"switch": "sw2", "port": 4, "mac": "fa:16:3e:a1:30:9f", "ip": "192.168.10.2"},
        "h3": {"switch": "sw2", "port": 5, "mac": "fa:16:3e:e0:26:a7", "ip": "192.168.10.3"},
        "h4": {"switch": "sw3", "port": 3, "mac": "fa:16:3e:e3:32:d5", "ip": "192.168.10.102"},
        "h5": {"switch": "sw3", "port": 4, "mac": "fa:16:3e:ce:27:f8", "ip": "192.168.10.101"},
        "app": {"switch": "sw5", "port": 4, "mac": "fa:16:3e:63:74:d0", "ip": "192.168.10.10"},
    },
    "switches": {
        "sw2": {"dpid": "00:00:00:00:00:00:00:02"},
        "sw3": {"dpid": "00:00:00:00:00:00:00:03"},
    },
}

CONFIG = {
    "floodlight_url": "http://127.0.0.1:8080",
    "topology_path": "/etc/sdn-g2/topology.json",
    "poll_interval_s": 1.0,
    "consecutive_windows": 3,
    "rule_prefix": "g2-r4-drop-",
    "drop_table": 0,
    "drop_priority": 1600,
    "base_timeout_s": 30,
    "escalated_timeout_s": 120,
    "recidivism_window_s": 180,
    "culprit_share_ratio": 0.25,
    "allowlist_ips": ["192.168.10.10"],
    "allowlist_cidrs": ["192.168.0.0/24"],
    "protected_servers": {
        "h5": {"label": "LMS", "capacity_mbps": 20.0, "threshold_ratio": 0.80, "pps_threshold": 1500},
        "h4": {"label": "Notas", "capacity_mbps": 20.0, "threshold_ratio": 0.80, "pps_threshold": 1500},
    },
}


class FakeFloodlight:
    def __init__(self):
        self.sw3 = {3: {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0},
                    4: {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0}}
        self.sw2 = {3: {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0},
                    4: {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0},
                    5: {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0}}
        self.sw2_flows = []
        self.pushed = []

    def port_stats(self, dpid):
        return {k: dict(v) for k, v in (self.sw3 if dpid.endswith(":03") else self.sw2).items()}

    def flow_rows(self, dpid):
        if dpid.endswith(":02"):
            rows = list(self.sw2_flows)
            for r in self.pushed:
                m = {k: v for k, v in r.items() if k in ("in_port", "ipv4_src", "ipv4_dst", "ip_proto", "tcp_dst", "udp_dst")}
                rows.append({"tableId": r["table"], "priority": r["priority"], "match": m, "instructions": {"none": "drop"}})
            return rows
        return []

    def push_flow(self, rule):
        self.pushed.append(rule)
        return {"status": "Entry pushed"}


class TestR4Engine(unittest.TestCase):
    def setUp(self):
        self.t = 100.0
        self.fl = FakeFloodlight()
        self.eng = R4Engine(CONFIG, TOPOLOGY, self.fl, store=None, clock=lambda: self.t)
        self.eng.step()  # init baseline

    def _advance(self, h5_mbps=0.0, h5_pps=0, h1_mbps=0.0, h2_mbps=0.0, h3_mbps=0.0, h2_pps=0):
        self.t += 1.0
        self.fl.sw3[4]["tx_bytes"] += int(h5_mbps * 1e6 / 8.0)
        self.fl.sw3[4]["tx_pkts"] += int(h5_pps)
        self.fl.sw2[3]["rx_bytes"] += int(h1_mbps * 1e6 / 8.0)
        self.fl.sw2[4]["rx_bytes"] += int(h2_mbps * 1e6 / 8.0)
        self.fl.sw2[4]["rx_pkts"] += int(h2_pps)
        self.fl.sw2[5]["rx_bytes"] += int(h3_mbps * 1e6 / 8.0)
        return self.eng.step()

    def test_short_burst_no_false_positive(self):
        # 2 s burst at 18 Mb/s (> 16 Mb/s), then back to normal -> 0 actions
        r1 = self._advance(h5_mbps=18, h2_mbps=9, h3_mbps=9)
        r2 = self._advance(h5_mbps=18, h2_mbps=9, h3_mbps=9)
        r3 = self._advance(h5_mbps=0.1, h1_mbps=0.1)
        self.assertEqual(r1["actions"], [])
        self.assertEqual(r2["actions"], [])
        self.assertEqual(r3["actions"], [])
        self.assertEqual(self.fl.pushed, [])

    def test_sustained_mbps_blocks_only_culprits_and_escalates(self):
        # 3 s sustained surge from h2 & h3 while h1 is legitimate (0.05 Mb/s)
        self._advance(h5_mbps=25, h1_mbps=0.05, h2_mbps=12.5, h3_mbps=12.5)
        self._advance(h5_mbps=25, h1_mbps=0.05, h2_mbps=12.5, h3_mbps=12.5)
        r3 = self._advance(h5_mbps=25, h1_mbps=0.05, h2_mbps=12.5, h3_mbps=12.5)
        blocked_clients = {a["client"] for a in r3["actions"]}
        self.assertEqual(blocked_clients, {"h2", "h3"})
        self.assertTrue(all(a["timeout_s"] == 30 and not a["escalated"] for a in r3["actions"]))
        # Simulate expiration after 35 s and re-offense within 180 s -> escalates to 120 s
        self.t += 35.0
        self._advance(h5_mbps=0.05, h1_mbps=0.05)  # clears consecutive & prunes expired
        self._advance(h5_mbps=22, h2_mbps=22)
        self._advance(h5_mbps=22, h2_mbps=22)
        r_esc = self._advance(h5_mbps=22, h2_mbps=22)
        self.assertEqual(len(r_esc["actions"]), 1)
        self.assertEqual(r_esc["actions"][0]["client"], "h2")
        self.assertEqual(r_esc["actions"][0]["timeout_s"], 120)
        self.assertTrue(r_esc["actions"][0]["escalated"])

    def test_small_packet_pps_flood_detected(self):
        # Low Mbps (1 Mb/s) but high PPS (2000 pps > 1500) from h2
        self._advance(h5_mbps=1.0, h5_pps=2000, h2_mbps=1.0, h2_pps=2000)
        self._advance(h5_mbps=1.0, h5_pps=2000, h2_mbps=1.0, h2_pps=2000)
        r3 = self._advance(h5_mbps=1.0, h5_pps=2000, h2_mbps=1.0, h2_pps=2000)
        self.assertEqual([a["client"] for a in r3["actions"]], ["h2"])
        self.assertEqual(r3["actions"][0]["reason"], "pps")


if __name__ == "__main__":
    unittest.main()
