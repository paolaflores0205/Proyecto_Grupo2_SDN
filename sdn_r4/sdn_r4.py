#!/usr/bin/env python3
"""SDN R4 volumetric detection and selective mitigation service (VNRT / Floodlight).

Features:
- Relative link-capacity thresholds (capacity_mbps * threshold_ratio) + pps threshold.
- Persistence window (default: 3 consecutive 1 s samples) to avoid short-burst false positives.
- Failover-safe measurement on sw3 egress ports toward protected servers (works with sw1 or sw4).
- Dynamic culprit (top-talker) identification on sw2 (L4 flow-level with L3 port-level fallback).
- Selective temporary DROP rules on sw2 table 0 (priority 1600) with allowlist & recidivism escalation.
- Structured JSONL audit log, atomic state snapshot, and DTI CLI (observe, status, unblock, cleanup).
"""

import argparse
import ipaddress
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def parse_num(value, default=0):
    if value is None:
        return default
    if isinstance(value, dict):
        value = value.get("value", value.get("portNumber", default))
    s = str(value).strip().lower()
    if not s or s in ("local", "any", "controller", "all", "normal"):
        return default
    while s.startswith("0x0x"):
        s = s[2:]
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return default


def strip_cidr(ip_val):
    return str(ip_val or "").split("/")[0].strip()


class FloodlightClient:
    def __init__(self, base_url, timeout=4.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with self._opener.open(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {}

    def port_stats(self, dpid):
        """Return {port_num_int: {'rx_bytes', 'tx_bytes', 'rx_pkts', 'tx_pkts'}}."""
        raw = self.request(f"/wm/core/switch/{dpid}/port/json")
        stats = {}
        replies = raw.get("port_reply", [])
        if isinstance(replies, dict):
            replies = [replies]
        for rep in replies:
            ports = rep.get("port", []) if isinstance(rep, dict) else []
            for p in ports:
                pnum = parse_num(p.get("portNumber"), default=-1)
                if pnum < 0:
                    continue
                stats[pnum] = {
                    "rx_bytes": parse_num(p.get("receiveBytes")),
                    "tx_bytes": parse_num(p.get("transmitBytes")),
                    "rx_pkts": parse_num(p.get("receivePackets")),
                    "tx_pkts": parse_num(p.get("transmitPackets")),
                }
        return stats

    def flow_rows(self, dpid):
        raw = self.request(f"/wm/core/switch/{dpid}/flow/json")
        result = []

        def walk(v):
            if isinstance(v, dict):
                if "priority" in v and "match" in v:
                    result.append(v)
                else:
                    for item in v.values():
                        walk(item)
            elif isinstance(v, list):
                for item in v:
                    walk(item)

        walk(raw)
        return result

    def push_flow(self, rule):
        reply = self.request("/wm/staticflowpusher/json", method="POST", body=rule)
        if "pushed" not in str(reply).lower():
            raise RuntimeError(f"Flow rejected by Floodlight: {reply}")
        return reply

    def delete_flow(self, name):
        return self.request("/wm/staticflowpusher/json", method="DELETE", body={"name": name})

    def list_static_flows(self):
        raw = self.request("/wm/staticflowpusher/list/all/json")
        names = {}
        for dpid, entries in raw.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        for k, v in entry.items():
                            names[k] = (dpid, v)
            elif isinstance(entries, dict):
                for k, v in entries.items():
                    names[k] = (dpid, v)
        return names


class AuditStore:
    def __init__(self, state_dir):
        path = Path(state_dir)
        try:
            path.mkdir(parents=True, exist_ok=True)
            test_file = path / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
            self.dir = path
        except OSError:
            fallback = Path(__file__).resolve().parent / "data"
            fallback.mkdir(parents=True, exist_ok=True)
            self.dir = fallback
        self.events_path = self.dir / "events.jsonl"
        self.state_path = self.dir / "state.json"

    def log_event(self, event_type, **fields):
        rec = {
            "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ts_epoch": round(time.time(), 3),
            "event": event_type,
        }
        rec.update(fields)
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def write_state(self, state):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.state_path)

    def read_state(self):
        if not self.state_path.exists():
            return None
        return json.loads(self.state_path.read_text(encoding="utf-8"))


class R4Engine:
    """Core volumetric detection and dynamic top-talker mitigation engine."""

    def __init__(self, config, topology, client, store=None, clock=None):
        self.cfg = config
        self.topo = topology
        self.client = client
        self.store = store
        self.clock = clock or time.monotonic

        self.sw2_dpid = topology["switches"]["sw2"]["dpid"]
        self.sw3_dpid = topology["switches"]["sw3"]["dpid"]
        self.prefix = config.get("rule_prefix", "g2-r4-drop-")
        self.drop_table = int(config.get("drop_table", 0))
        self.drop_priority = int(config.get("drop_priority", 1600))
        self.consecutive_needed = int(config.get("consecutive_windows", 3))
        self.base_timeout = int(config.get("base_timeout_s", 30))
        self.escalated_timeout = int(config.get("escalated_timeout_s", 120))
        self.recidivism_window = float(config.get("recidivism_window_s", 180))
        self.culprit_share = float(config.get("culprit_share_ratio", 0.25))

        self.allowlist_ips = set(config.get("allowlist_ips", []))
        self.allowlist_nets = [
            ipaddress.ip_network(c, strict=False) for c in config.get("allowlist_cidrs", [])
        ]

        # Build client map on sw2 and server map on sw3 from topology.json
        self.clients = {}
        for cname in topology.get("clients", []):
            node = topology["nodes"].get(cname)
            if node and node.get("switch") == "sw2":
                self.clients[cname] = {
                    "name": cname,
                    "port": int(node["port"]),
                    "mac": node["mac"].lower(),
                    "ip": node["ip"],
                }

        self.servers = {}
        for sname, scfg in config.get("protected_servers", {}).items():
            node = topology["nodes"].get(sname)
            if node and node.get("switch") == "sw3":
                cap = float(scfg["capacity_mbps"])
                ratio = float(scfg.get("threshold_ratio", 0.80))
                self.servers[sname] = {
                    "name": sname,
                    "label": scfg.get("label", sname),
                    "port": int(node["port"]),
                    "mac": node["mac"].lower(),
                    "ip": node["ip"],
                    "capacity_mbps": cap,
                    "mbps_threshold": round(cap * ratio, 4),
                    "pps_threshold": float(scfg.get("pps_threshold", 1500)),
                }

        # Runtime state
        self.prev_t = None
        self.prev_sw3_ports = None
        self.prev_sw2_ports = None
        self.prev_sw2_flows = None
        self.consecutive = {s: 0 for s in self.servers}
        self.active_drops = {}  # rule_name -> metadata dict
        self.offense_history = {}  # (client_ip, server_ip) -> last_mitigated_monotonic
        self.latest_metrics = {}

    def is_allowlisted(self, ip_str):
        ip_clean = strip_cidr(ip_str)
        if not ip_clean:
            return True
        if ip_clean in self.allowlist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip_clean)
            return any(addr in net for net in self.allowlist_nets)
        except ValueError:
            return True

    @staticmethod
    def _flow_key(row):
        m = row.get("match", {})
        return json.dumps(
            [
                parse_num(row.get("tableId", 0)),
                parse_num(row.get("priority", 0)),
                parse_num(m.get("in_port", -1)),
                strip_cidr(m.get("ipv4_src", "")),
                strip_cidr(m.get("ipv4_dst", "")),
                parse_num(m.get("ip_proto", 0)),
                parse_num(m.get("tcp_dst", m.get("udp_dst", 0))),
            ]
        )

    def _index_sw2_flows(self, rows):
        indexed = {}
        for r in rows:
            m = r.get("match", {})
            sip = strip_cidr(m.get("ipv4_src", ""))
            dip = strip_cidr(m.get("ipv4_dst", ""))
            if not sip or not dip:
                continue
            key = self._flow_key(r)
            indexed[key] = {
                "bytes": parse_num(r.get("byteCount")),
                "pkts": parse_num(r.get("packetCount")),
                "in_port": parse_num(m.get("in_port", -1)),
                "ipv4_src": sip,
                "ipv4_dst": dip,
                "ip_proto": parse_num(m.get("ip_proto", 0)),
                "tcp_dst": parse_num(m.get("tcp_dst", 0)),
                "udp_dst": parse_num(m.get("udp_dst", 0)),
            }
        return indexed

    def _client_by_ip(self, ip_str):
        for c in self.clients.values():
            if c["ip"] == ip_str:
                return c
        return None

    def _prune_expired_drops(self, now):
        expired = [name for name, meta in self.active_drops.items() if now >= meta["expires_mono"]]
        for name in expired:
            meta = self.active_drops.pop(name)
            if self.store:
                self.store.log_event("expire", rule_name=name, client=meta["client"], server=meta["server"])

    def _identify_culprits(self, server, dt, sw2_port_deltas, sw2_flow_deltas):
        """Return list of culprit descriptors: L4 flow-level first, L3 port-level fallback."""
        sip_candidates = []
        mbps_cut = server["mbps_threshold"] * self.culprit_share
        pps_cut = server["pps_threshold"] * self.culprit_share

        # 1. Try pinpoint L4 flow-level detection on sw2 toward this server
        for fmeta in sw2_flow_deltas:
            if fmeta["ipv4_dst"] != server["ip"]:
                continue
            if self.is_allowlisted(fmeta["ipv4_src"]):
                continue
            client = self._client_by_ip(fmeta["ipv4_src"])
            if not client:
                continue
            if fmeta["mbps"] >= mbps_cut or fmeta["pps"] >= pps_cut:
                proto = fmeta["ip_proto"]
                dst_port = fmeta["tcp_dst"] if proto == 6 else (fmeta["udp_dst"] if proto == 17 else 0)
                sip_candidates.append(
                    {
                        "scope": "l4" if (proto in (6, 17) and dst_port > 0) else "l3",
                        "client": client["name"],
                        "client_ip": client["ip"],
                        "client_mac": client["mac"],
                        "in_port": client["port"],
                        "server": server["name"],
                        "server_ip": server["ip"],
                        "ip_proto": proto,
                        "dst_port": dst_port,
                        "mbps": round(fmeta["mbps"], 3),
                        "pps": round(fmeta["pps"], 1),
                    }
                )

        if sip_candidates:
            return sip_candidates

        # 2. Fallback: port-level top-talkers on sw2 (handles multi-port / aggregated floods)
        for cname, client in self.clients.items():
            if self.is_allowlisted(client["ip"]):
                continue
            delta = sw2_port_deltas.get(client["port"], {"mbps": 0.0, "pps": 0.0})
            if delta["mbps"] >= mbps_cut or delta["pps"] >= pps_cut:
                sip_candidates.append(
                    {
                        "scope": "l3",
                        "client": cname,
                        "client_ip": client["ip"],
                        "client_mac": client["mac"],
                        "in_port": client["port"],
                        "server": server["name"],
                        "server_ip": server["ip"],
                        "ip_proto": 0,
                        "dst_port": 0,
                        "mbps": round(delta["mbps"], 3),
                        "pps": round(delta["pps"], 1),
                    }
                )
        return sip_candidates

    def _build_drop_rule(self, culprit, timeout_s):
        proto_tag = (
            f"tcp{culprit['dst_port']}"
            if culprit["ip_proto"] == 6 and culprit["dst_port"]
            else (
                f"udp{culprit['dst_port']}"
                if culprit["ip_proto"] == 17 and culprit["dst_port"]
                else "all"
            )
        )
        name = f"{self.prefix}{culprit['client']}-{culprit['server']}-{proto_tag}"
        rule = {
            "switch": self.sw2_dpid,
            "name": name,
            "table": str(self.drop_table),
            "priority": str(self.drop_priority),
            "active": "true",
            "idle_timeout": "0",
            "hard_timeout": str(timeout_s),
            "in_port": str(culprit["in_port"]),
            "eth_type": "0x0800",
            "eth_src": culprit["client_mac"],
            "ipv4_src": f"{culprit['client_ip']}/32",
            "ipv4_dst": f"{culprit['server_ip']}/32",
            "actions": "",
        }
        if culprit["scope"] == "l4" and culprit["ip_proto"] in (6, 17) and culprit["dst_port"] > 0:
            rule["ip_proto"] = str(culprit["ip_proto"])
            rule["tcp_dst" if culprit["ip_proto"] == 6 else "udp_dst"] = str(culprit["dst_port"])
        return rule

    def _verify_drop_present(self, rule):
        rows = self.client.flow_rows(self.sw2_dpid)
        for r in rows:
            if parse_num(r.get("tableId", -1)) != self.drop_table:
                continue
            if parse_num(r.get("priority", 0)) != self.drop_priority:
                continue
            m = r.get("match", {})
            if parse_num(m.get("in_port", -1)) != parse_num(rule["in_port"]):
                continue
            if strip_cidr(m.get("ipv4_src")) != strip_cidr(rule["ipv4_src"]):
                continue
            if strip_cidr(m.get("ipv4_dst")) != strip_cidr(rule["ipv4_dst"]):
                continue
            if "ip_proto" in rule and parse_num(m.get("ip_proto", 0)) != parse_num(rule["ip_proto"]):
                continue
            if "tcp_dst" in rule and parse_num(m.get("tcp_dst", 0)) != parse_num(rule["tcp_dst"]):
                continue
            if "udp_dst" in rule and parse_num(m.get("udp_dst", 0)) != parse_num(rule["udp_dst"]):
                continue
            ins = r.get("instructions", {})
            actions = ins.get("instruction_apply_actions", {}).get("actions", "")
            if not actions:
                return True
        return False

    def step(self, dry_run=False):
        """Execute one polling cycle; returns summary dict of metrics and any actions."""
        now = self.clock()
        self._prune_expired_drops(now)

        sw3_ports = self.client.port_stats(self.sw3_dpid)
        sw2_ports = self.client.port_stats(self.sw2_dpid)
        sw2_flows = self._index_sw2_flows(self.client.flow_rows(self.sw2_dpid))

        if self.prev_t is None:
            self.prev_t = now
            self.prev_sw3_ports = sw3_ports
            self.prev_sw2_ports = sw2_ports
            self.prev_sw2_flows = sw2_flows
            return {"initialized": True, "servers": {}, "actions": []}

        dt = max(now - self.prev_t, 0.001)

        # Compute sw2 client port deltas (ingress from clients into sw2)
        sw2_port_deltas = {}
        for cname, client in self.clients.items():
            p = client["port"]
            cur = sw2_ports.get(p, {})
            prv = self.prev_sw2_ports.get(p, cur)
            d_bytes = max(0, cur.get("rx_bytes", 0) - prv.get("rx_bytes", 0))
            d_pkts = max(0, cur.get("rx_pkts", 0) - prv.get("rx_pkts", 0))
            sw2_port_deltas[p] = {
                "client": cname,
                "mbps": 8.0 * d_bytes / (dt * 1e6),
                "pps": d_pkts / dt,
            }

        # Compute sw2 flow deltas
        sw2_flow_deltas = []
        for key, cur in sw2_flows.items():
            prv = self.prev_sw2_flows.get(key)
            if not prv:
                continue
            d_bytes = max(0, cur["bytes"] - prv["bytes"])
            d_pkts = max(0, cur["pkts"] - prv["pkts"])
            if d_bytes == 0 and d_pkts == 0:
                continue
            sw2_flow_deltas.append(
                {
                    **cur,
                    "mbps": 8.0 * d_bytes / (dt * 1e6),
                    "pps": d_pkts / dt,
                }
            )

        # Compute sw3 server egress deltas (independent of sw1/sw4 uplink!)
        server_summary = {}
        actions_taken = []
        for sname, server in self.servers.items():
            p = server["port"]
            cur = sw3_ports.get(p, {})
            prv = self.prev_sw3_ports.get(p, cur)
            d_bytes = max(0, cur.get("tx_bytes", 0) - prv.get("tx_bytes", 0))
            d_pkts = max(0, cur.get("tx_pkts", 0) - prv.get("tx_pkts", 0))
            mbps = 8.0 * d_bytes / (dt * 1e6)
            pps = d_pkts / dt

            over_mbps = mbps > server["mbps_threshold"]
            over_pps = pps > server["pps_threshold"]
            if over_mbps or over_pps:
                self.consecutive[sname] += 1
            else:
                self.consecutive[sname] = 0

            server_summary[sname] = {
                "label": server["label"],
                "ip": server["ip"],
                "tx_mbps": round(mbps, 4),
                "tx_pps": round(pps, 1),
                "mbps_threshold": server["mbps_threshold"],
                "pps_threshold": server["pps_threshold"],
                "consecutive": self.consecutive[sname],
                "over_mbps": over_mbps,
                "over_pps": over_pps,
            }

            if self.consecutive[sname] >= self.consecutive_needed:
                reason = "mbps+pps" if (over_mbps and over_pps) else ("mbps" if over_mbps else "pps")
                culprits = self._identify_culprits(server, dt, sw2_port_deltas, sw2_flow_deltas)
                if self.store:
                    self.store.log_event(
                        "detect",
                        server=sname,
                        server_ip=server["ip"],
                        reason=reason,
                        tx_mbps=round(mbps, 4),
                        tx_pps=round(pps, 1),
                        culprits=culprits,
                        dry_run=dry_run,
                    )
                for culprit in culprits:
                    pair = (culprit["client_ip"], culprit["server_ip"])
                    last_offense = self.offense_history.get(pair)
                    escalated = (
                        last_offense is not None
                        and (now - last_offense) <= self.recidivism_window
                    )
                    timeout_s = self.escalated_timeout if escalated else self.base_timeout
                    rule = self._build_drop_rule(culprit, timeout_s)
                    if rule["name"] in self.active_drops:
                        continue
                    action_rec = {
                        "rule_name": rule["name"],
                        "client": culprit["client"],
                        "server": sname,
                        "scope": culprit["scope"],
                        "timeout_s": timeout_s,
                        "escalated": escalated,
                        "reason": reason,
                        "dry_run": dry_run,
                    }
                    if not dry_run:
                        t_dec = self.clock()
                        self.client.push_flow(rule)
                        verified = False
                        deadline = self.clock() + 3.0
                        while self.clock() <= deadline:
                            if self._verify_drop_present(rule):
                                verified = True
                                break
                            time.sleep(0.1)
                        t_app = self.clock()
                        action_rec["verified"] = verified
                        action_rec["apply_s"] = round(t_app - t_dec, 4)
                        self.active_drops[rule["name"]] = {
                            "rule": rule,
                            "client": culprit["client"],
                            "client_ip": culprit["client_ip"],
                            "server": sname,
                            "server_ip": server["ip"],
                            "timeout_s": timeout_s,
                            "escalated": escalated,
                            "installed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "expires_mono": now + timeout_s,
                        }
                        self.offense_history[pair] = now
                        if self.store:
                            self.store.log_event(
                                "escalate" if escalated else "mitigate",
                                **action_rec,
                            )
                    actions_taken.append(action_rec)

        self.prev_t = now
        self.prev_sw3_ports = sw3_ports
        self.prev_sw2_ports = sw2_ports
        self.prev_sw2_flows = sw2_flows
        self.latest_metrics = {
            "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "servers": server_summary,
            "clients": {
                v["client"]: {"rx_mbps": round(v["mbps"], 4), "rx_pps": round(v["pps"], 1)}
                for v in sw2_port_deltas.values()
            },
            "active_drops": [
                {
                    "rule_name": k,
                    "client": v["client"],
                    "client_ip": v["client_ip"],
                    "server": v["server"],
                    "timeout_s": v["timeout_s"],
                    "escalated": v["escalated"],
                    "installed_utc": v["installed_utc"],
                    "remaining_s": max(0, round(v["expires_mono"] - now, 1)),
                }
                for k, v in self.active_drops.items()
            ],
        }
        if self.store and not dry_run:
            self.store.write_state(self.latest_metrics)
        return {"initialized": False, "servers": server_summary, "actions": actions_taken}


def load_config(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_daemon(args):
    cfg = load_config(args.config)
    topo = json.loads(Path(cfg["topology_path"]).read_text(encoding="utf-8"))
    client = FloodlightClient(cfg["floodlight_url"])
    store = AuditStore(cfg.get("state_dir", "/var/lib/sdn-r4"))
    engine = R4Engine(cfg, topo, client, store=store)
    poll = float(cfg.get("poll_interval_s", 1.0))

    stop = False

    def handle_sig(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    store.log_event("start", pid=os.getpid(), servers=list(engine.servers.keys()))
    while not stop:
        t0 = time.monotonic()
        try:
            engine.step(dry_run=False)
        except Exception as exc:
            store.log_event("error", message=str(exc))
        elapsed = time.monotonic() - t0
        sleep_s = max(0.05, poll - elapsed)
        end_sleep = time.monotonic() + sleep_s
        while not stop and time.monotonic() < end_sleep:
            time.sleep(min(0.2, max(0.0, end_sleep - time.monotonic())))

    store.log_event("stop", pid=os.getpid())


def cmd_observe(args):
    cfg = load_config(args.config)
    topo = json.loads(Path(cfg["topology_path"]).read_text(encoding="utf-8"))
    client = FloodlightClient(cfg["floodlight_url"])
    engine = R4Engine(cfg, topo, client, store=None)
    poll = float(cfg.get("poll_interval_s", 1.0))
    for i in range(args.seconds + 1):
        res = engine.step(dry_run=True)
        if not res["initialized"]:
            print(json.dumps({"sample": i, "servers": res["servers"], "clients": engine.latest_metrics["clients"], "would_mitigate": res["actions"]}))
        if i < args.seconds:
            time.sleep(poll)


def cmd_status(args):
    cfg = load_config(args.config)
    store = AuditStore(cfg.get("state_dir", "/var/lib/sdn-r4"))
    client = FloodlightClient(cfg["floodlight_url"])
    prefix = cfg.get("rule_prefix", "g2-r4-drop-")
    static = client.list_static_flows()
    r4_rules = sorted(k for k in static if k.startswith(prefix))
    out = {
        "state_dir": str(store.dir),
        "active_r4_static_rules": r4_rules,
        "last_state": store.read_state(),
    }
    print(json.dumps(out, indent=2))


def cmd_unblock(args):
    cfg = load_config(args.config)
    store = AuditStore(cfg.get("state_dir", "/var/lib/sdn-r4"))
    client = FloodlightClient(cfg["floodlight_url"])
    prefix = cfg.get("rule_prefix", "g2-r4-drop-")
    static = client.list_static_flows()
    removed = []
    for name, (_dpid, body) in static.items():
        if not name.startswith(prefix):
            continue
        match = body.get("match", {}) if isinstance(body, dict) else {}
        src_ip = strip_cidr(match.get("ipv4_src", ""))
        if args.target in (name, src_ip) or args.target in name:
            client.delete_flow(name)
            removed.append(name)
            store.log_event("manual_unblock", rule_name=name, target=args.target, reason=args.reason)
    print(json.dumps({"removed": removed}, indent=2))


def cmd_cleanup(args):
    cfg = load_config(args.config)
    store = AuditStore(cfg.get("state_dir", "/var/lib/sdn-r4"))
    client = FloodlightClient(cfg["floodlight_url"])
    prefix = cfg.get("rule_prefix", "g2-r4-drop-")
    static = client.list_static_flows()
    removed = []
    for name in sorted(k for k in static if k.startswith(prefix)):
        client.delete_flow(name)
        removed.append(name)
    store.log_event("cleanup", removed=removed)
    print(json.dumps({"removed": removed}, indent=2))


def main():
    p = argparse.ArgumentParser(description="SDN R4 volumetric protection daemon & DTI CLI")
    p.add_argument("--config", default=os.environ.get("SDN_R4_CONFIG", "/etc/sdn-r4/config.json"))
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("daemon", help="Run continuous R4 volumetric monitor & mitigator")

    obs = sub.add_parser("observe", help="Read-only live telemetry check (no flow changes)")
    obs.add_argument("--seconds", type=int, default=5)

    sub.add_parser("status", help="Show active R4 drops and latest metrics")

    ub = sub.add_parser("unblock", help="DTI manual unblock by rule name, host or IP")
    ub.add_argument("target", help="Rule name, client name (e.g. h2) or IPv4")
    ub.add_argument("--reason", default="false_positive_review")

    sub.add_parser("cleanup", help="Remove all g2-r4-drop-* rules from Floodlight")

    args = p.parse_args()
    if args.cmd == "daemon":
        cmd_daemon(args)
    elif args.cmd == "observe":
        cmd_observe(args)
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "unblock":
        cmd_unblock(args)
    elif args.cmd == "cleanup":
        cmd_cleanup(args)


if __name__ == "__main__":
    main()
