#!/usr/bin/env python3
"""Live end-to-end validation of sdn-r4.service on VNRT.

Tests against the running sdn-r4.service daemon on `app`:
1. Sustained legitimate load below threshold (12 Mb/s for 6 s) -> 0 blocks.
2. Short burst above threshold (20 Mb/s for 2 s) -> 0 false positives.
3. Sustained overload (24 Mb/s for 10 s from h2+h3 while h1 sends 0.5 Mb/s) ->
   automatic dynamic DROP for h2 & h3 only (30 s), h1 untouched.
4. DTI manual unblock (`sdn_r4.py unblock h3`) -> removes h3 rule immediately.
5. Natural expiration of h2's 30 s DROP + small-packet PPS flood (~2200 pps, ~1.2 Mb/s) ->
   detected by PPS threshold AND escalated to 120 s due to recidivism.
Always cleans up all temporary test-permit rules, R4 drop rules, and iperf3 servers.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

APP = "app"
HOSTS = {
    "h1": {"ssh": "192.168.0.21", "ip": "192.168.10.1", "mac": "fa:16:3e:53:96:3e", "sw2_port": 3, "udp_port": 5203},
    "h2": {"ssh": "192.168.0.22", "ip": "192.168.10.2", "mac": "fa:16:3e:a1:30:9f", "sw2_port": 4, "udp_port": 5201},
    "h3": {"ssh": "192.168.0.23", "ip": "192.168.10.3", "mac": "fa:16:3e:e0:26:a7", "sw2_port": 5, "udp_port": 5202},
    "h5": {"ssh": "192.168.0.25", "ip": "192.168.10.101", "mac": "fa:16:3e:ce:27:f8", "sw3_port": 4},
}
DPIDS = {
    "sw1": "00:00:00:00:00:00:00:01",
    "sw2": "00:00:00:00:00:00:00:02",
    "sw3": "00:00:00:00:00:00:00:03",
}
PERMIT_PREFIX = "g2-r4-testpermit-"


def ssh(target, cmd, timeout=45, check=True):
    res = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", target, cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"SSH {target} failed ({res.returncode}): {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout.strip()


def ssh_popen(target, cmd):
    return subprocess.Popen(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", target, cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def build_test_permits():
    """Temporary L4 permits (priority 1501, hard_timeout 240s) for h1/h2/h3 -> h5 TCP/UDP 5201-5203."""
    rules = []
    h5 = HOSTS["h5"]
    for cname in ("h1", "h2", "h3"):
        c = HOSTS[cname]
        port = c["udp_port"]
        # Path: sw2 (c.sw2_port -> 1) -> sw1 (1 -> 2) -> sw3 (1 -> 4)
        hops = [("sw2", c["sw2_port"], 1), ("sw1", 1, 2), ("sw3", 1, h5["sw3_port"])]
        for proto in (6, 17):
            pfield_fwd = "tcp_dst" if proto == 6 else "udp_dst"
            pfield_rev = "tcp_src" if proto == 6 else "udp_src"
            ptag = "tcp" if proto == 6 else "udp"
            for sw, ing, egr in hops:
                rules.append({
                    "switch": DPIDS[sw],
                    "name": f"{PERMIT_PREFIX}{cname}-{ptag}{port}-{sw}-fwd",
                    "table": "0", "priority": "1501", "active": "true",
                    "idle_timeout": "0", "hard_timeout": "240",
                    "in_port": str(ing), "eth_type": "0x0800",
                    "eth_src": c["mac"], "eth_dst": h5["mac"],
                    "ipv4_src": f"{c['ip']}/32", "ipv4_dst": f"{h5['ip']}/32",
                    "ip_proto": str(proto), pfield_fwd: str(port),
                    "actions": f"output={egr}",
                })
                rules.append({
                    "switch": DPIDS[sw],
                    "name": f"{PERMIT_PREFIX}{cname}-{ptag}{port}-{sw}-rev",
                    "table": "0", "priority": "1501", "active": "true",
                    "idle_timeout": "0", "hard_timeout": "240",
                    "in_port": str(egr), "eth_type": "0x0800",
                    "eth_src": h5["mac"], "eth_dst": c["mac"],
                    "ipv4_src": f"{h5['ip']}/32", "ipv4_dst": f"{c['ip']}/32",
                    "ip_proto": str(proto), pfield_rev: str(port),
                    "actions": f"output={ing}",
                })
    return rules


def push_permits(rules):
    payload = json.dumps(rules)
    py_cmd = (
        "python3 -c 'import sys,json,urllib.request; "
        "rules=json.load(sys.stdin); "
        "[urllib.request.urlopen(urllib.request.Request("
        "\"http://127.0.0.1:8080/wm/staticflowpusher/json\", "
        "data=json.dumps(r).encode(), method=\"POST\", "
        "headers={\"Content-Type\":\"application/json\"}), timeout=5).read() for r in rules]; "
        "print(len(rules))'"
    )
    res = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", APP, py_cmd],
        input=payload, capture_output=True, text=True, timeout=30,
    )
    if res.returncode != 0:
        raise RuntimeError(f"push_permits failed: {res.stderr}")
    return int(res.stdout.strip())


def delete_permits(rules):
    names = [r["name"] for r in rules]
    payload = json.dumps(names)
    py_cmd = (
        "python3 -c 'import sys,json,urllib.request; "
        "names=json.load(sys.stdin); "
        "[urllib.request.urlopen(urllib.request.Request("
        "\"http://127.0.0.1:8080/wm/staticflowpusher/json\", "
        "data=json.dumps({\"name\":n}).encode(), method=\"DELETE\", "
        "headers={\"Content-Type\":\"application/json\"}), timeout=5).read() for n in names]; "
        "print(len(names))'"
    )
    subprocess.run(
        ["ssh", "-o", "BatchMode=yes", APP, py_cmd],
        input=payload, capture_output=True, text=True, timeout=30,
    )


def r4_status():
    return json.loads(ssh(APP, "python3 /opt/sdn-r4/sdn_r4.py status"))


def r4_events_since(ts_epoch):
    raw = ssh(APP, "cat /var/lib/sdn-r4/events.jsonl 2>/dev/null || true")
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        if ev.get("ts_epoch", 0) >= ts_epoch:
            events.append(ev)
    return events


def parse_iperf_json(stdout_text):
    try:
        data = json.loads(stdout_text)
        end = data.get("end", {})
        sum_obj = end.get("sum", end.get("sum_received", {}))
        intervals = [
            round(iv.get("sum", {}).get("bits_per_second", 0) / 1e6, 2)
            for iv in data.get("intervals", [])
        ]
        return {
            "sent_mbps": round(sum_obj.get("bits_per_second", 0) / 1e6, 2),
            "lost_percent": round(sum_obj.get("lost_percent", -1), 2),
            "packets": sum_obj.get("packets", 0),
            "lost_packets": sum_obj.get("lost_packets", 0),
            "intervals_mbps": intervals,
        }
    except Exception as exc:
        return {"error": str(exc), "raw_tail": stdout_text[-200:]}


def main():
    report = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tests": {}}
    permits = build_test_permits()
    start_epoch = time.time() - 1.0

    # Preflight
    svc = ssh(APP, "systemctl is-active sdn-r4.service")
    assert svc == "active", f"sdn-r4.service not active: {svc}"
    st0 = r4_status()
    assert st0["active_r4_static_rules"] == [], f"Unexpected pre-existing R4 rules: {st0['active_r4_static_rules']}"
    report["preflight"] = {"service": svc, "initial_r4_rules": 0}

    try:
        # Clean any stale testpermits from previous runs, then install fresh permits & start iperf3 servers on h5
        delete_permits(permits)
        time.sleep(0.5)
        n_pushed = push_permits(permits)
        report["setup_permits"] = n_pushed
        ssh(HOSTS["h5"]["ssh"], "pkill -x iperf3 2>/dev/null || true; sleep 0.3; "
            "iperf3 -s -D -B 192.168.10.101 -p 5201 && "
            "iperf3 -s -D -B 192.168.10.101 -p 5202 && "
            "iperf3 -s -D -B 192.168.10.101 -p 5203 && sleep 0.3")

        # TEST 1: Sustained legitimate load below threshold (6 + 6 = 12 Mb/s for 6 s)
        print("[1/5] Test 1: 12 Mb/s sustained (6 s) -> expect 0 blocks...", flush=True)
        p2 = ssh_popen(HOSTS["h2"]["ssh"], "iperf3 -c 192.168.10.101 -p 5201 --connect-timeout 5000 -u -b 6M -l 1200 -t 6 -J")
        p3 = ssh_popen(HOSTS["h3"]["ssh"], "iperf3 -c 192.168.10.101 -p 5202 --connect-timeout 5000 -u -b 6M -l 1200 -t 6 -J")
        o2, _ = p2.communicate(timeout=45)
        o3, _ = p3.communicate(timeout=45)
        time.sleep(2.0)
        st1 = r4_status()
        report["tests"]["T1_sustained_12mbps"] = {
            "h2": parse_iperf_json(o2),
            "h3": parse_iperf_json(o3),
            "active_r4_rules": st1["active_r4_static_rules"],
            "pass": len(st1["active_r4_static_rules"]) == 0,
        }

        # TEST 2: Short burst above threshold (10 + 10 = 20 Mb/s for only 2 s)
        print("[2/5] Test 2: 20 Mb/s short burst (2 s) -> expect 0 false positives...", flush=True)
        p2 = ssh_popen(HOSTS["h2"]["ssh"], "iperf3 -c 192.168.10.101 -p 5201 --connect-timeout 5000 -u -b 10M -l 1200 -t 2 -J")
        p3 = ssh_popen(HOSTS["h3"]["ssh"], "iperf3 -c 192.168.10.101 -p 5202 --connect-timeout 5000 -u -b 10M -l 1200 -t 2 -J")
        o2, _ = p2.communicate(timeout=45)
        o3, _ = p3.communicate(timeout=45)
        time.sleep(2.5)
        st2 = r4_status()
        report["tests"]["T2_short_burst_20mbps_2s"] = {
            "h2": parse_iperf_json(o2),
            "h3": parse_iperf_json(o3),
            "active_r4_rules": st2["active_r4_static_rules"],
            "pass": len(st2["active_r4_static_rules"]) == 0,
        }

        # TEST 3: Sustained overload (12 + 12 = 24 Mb/s for 10 s) while h1 sends legitimate traffic
        print("[3/5] Test 3: 24 Mb/s overload (h2+h3) + legitimate h1 probe -> expect DROP h2 & h3 only...", flush=True)
        p1 = ssh_popen(HOSTS["h1"]["ssh"],
            "python3 -c 'import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            "ok=0\nfor _ in range(9):\n s.sendto(b\"legit\"*20,(\"192.168.10.101\",5203)); ok+=1; time.sleep(1)\nprint(ok)'")
        p2 = ssh_popen(HOSTS["h2"]["ssh"], "iperf3 -c 192.168.10.101 -p 5201 --connect-timeout 5000 -u -b 12M -l 1200 -t 10 -J")
        p3 = ssh_popen(HOSTS["h3"]["ssh"], "iperf3 -c 192.168.10.101 -p 5202 --connect-timeout 5000 -u -b 12M -l 1200 -t 10 -J")
        # Poll status at t=7s (while overload is active and DROP should be installed)
        time.sleep(7.0)
        st3_mid = r4_status()
        o1, _ = p1.communicate(timeout=45)
        o2, _ = p2.communicate(timeout=45)
        o3, _ = p3.communicate(timeout=45)
        st3_after = r4_status()
        # Check h1 TCP connectivity to h5:5203 is STILL open while h2 & h3 are blocked!
        h1_tcp_ok = ssh(HOSTS["h1"]["ssh"],
            "python3 -c 'import socket; s=socket.create_connection((\"192.168.10.101\",5203),timeout=2); s.close(); print(\"OK\")'",
            check=False)
        rules_t3 = st3_after["active_r4_static_rules"]
        report["tests"]["T3_overload_24mbps_selective_drop"] = {
            "h2": parse_iperf_json(o2),
            "h3": parse_iperf_json(o3),
            "h1_udp_sent": o1.strip(),
            "h1_tcp_5203_during_block": h1_tcp_ok,
            "active_r4_rules_mid": st3_mid["active_r4_static_rules"],
            "active_r4_rules_after": rules_t3,
            "last_state_mid": st3_mid["last_state"],
            "pass": (
                any("h2" in r for r in rules_t3)
                and any("h3" in r for r in rules_t3)
                and not any("h1" in r for r in rules_t3)
                and h1_tcp_ok == "OK"
            ),
        }

        # TEST 4: DTI manual unblock of h3 while h2 remains blocked
        print("[4/5] Test 4: DTI manual unblock of h3 -> expect h3 removed, h2 still blocked...")
        ub_out = json.loads(ssh(APP, "python3 /opt/sdn-r4/sdn_r4.py unblock h3 --reason prueba_dti"))
        time.sleep(0.5)
        st4 = r4_status()
        report["tests"]["T4_dti_manual_unblock_h3"] = {
            "unblock_output": ub_out,
            "remaining_rules": st4["active_r4_static_rules"],
            "pass": (
                any("h3" in r for r in ub_out.get("removed", []))
                and not any("h3" in r for r in st4["active_r4_static_rules"])
                and any("h2" in r for r in st4["active_r4_static_rules"])
            ),
        }

        # TEST 5: Wait for h2's 30 s DROP to expire naturally, then send small-packet PPS flood (~2200 pps, ~1.2 Mb/s)
        print("[5/5] Test 5: Waiting for h2 natural 30s expiration, then small-packet PPS flood (~2200 pps) + recidivism escalation (120s)...")
        expired_ok = False
        wait_t0 = time.monotonic()
        while time.monotonic() - wait_t0 < 40.0:
            st_w = r4_status()
            active_in_daemon = st_w.get("last_state", {}).get("active_drops", [])
            if not active_in_daemon:
                expired_ok = True
                break
            time.sleep(2.0)
        # Also confirm static list clean or wait 1s
        time.sleep(1.5)
        # Send ~2200 pps of 64-byte UDP packets from h2 -> h5:5201 (~1.13 Mb/s << 16 Mb/s, but > 1500 pps!)
        # 2200 pkt/s * 64 B * 8 = 1,126,400 bps = 1.13M
        p2_pps = ssh_popen(HOSTS["h2"]["ssh"], "iperf3 -c 192.168.10.101 -p 5201 --connect-timeout 5000 -u -b 1.2M -l 64 -t 9 -J")
        o2_pps, _ = p2_pps.communicate(timeout=45)
        time.sleep(1.0)
        st5 = r4_status()
        evs = r4_events_since(start_epoch)
        esc_evs = [e for e in evs if e.get("event") == "escalate" and e.get("client") == "h2"]
        report["tests"]["T5_expire_and_pps_escalation"] = {
            "natural_expiration_observed": expired_ok,
            "wait_seconds": round(time.monotonic() - wait_t0, 1),
            "h2_pps_flood": parse_iperf_json(o2_pps),
            "active_r4_rules_after": st5["active_r4_static_rules"],
            "active_drops_state": st5.get("last_state", {}).get("active_drops", []),
            "escalation_events": esc_evs,
            "pass": (
                expired_ok
                and len(esc_evs) >= 1
                and esc_evs[-1].get("timeout_s") == 120
                and esc_evs[-1].get("reason") == "pps"
            ),
        }
        report["events_recorded"] = evs

    finally:
        print("[cleanup] Cleaning up R4 drops, test permits, and iperf3 servers...")
        cleanup_out = ssh(APP, "python3 /opt/sdn-r4/sdn_r4.py cleanup", check=False)
        delete_permits(permits)
        ssh(HOSTS["h5"]["ssh"], "pkill -x iperf3 2>/dev/null || true", check=False)
        time.sleep(0.5)
        st_end = r4_status()
        iperf_left = ssh(HOSTS["h5"]["ssh"], "pgrep -a iperf3 || true", check=False)
        report["cleanup"] = {
            "r4_cleanup": cleanup_out,
            "remaining_r4_rules": st_end["active_r4_static_rules"],
            "iperf3_left_on_h5": iperf_left,
            "service_still_active": ssh(APP, "systemctl is-active sdn-r4.service", check=False),
        }

    out_path = Path(__file__).resolve().parent / "live_vnrt_test_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("=== SUMMARY ===")
    for k, v in report["tests"].items():
        print(f"  {k}: PASS={v['pass']}")
    print(f"  Cleanup remaining_r4_rules={report['cleanup']['remaining_r4_rules']}, service={report['cleanup']['service_still_active']}")
    print(f"Full report saved to: {out_path}")


if __name__ == "__main__":
    main()
