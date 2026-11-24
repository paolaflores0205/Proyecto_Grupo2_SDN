"""Datos de prueba compartidos.

Las lineas REAL_* son eventos reales del Suricata principal de la maqueta (VM suricata,
Suricata 7.0.3, 15-17 de noviembre de 2026). Las demas son sinteticas, con el mismo
formato, para escenarios perimetrales que aun no ocurrieron en la maqueta.
"""
import json
from pathlib import Path

from r5 import ThreatIntel, load_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "config" / "policy.json")
BLACKLIST_TEXT = (ROOT / "config" / "blacklist.txt").read_text(encoding="utf-8")


def make_intel() -> ThreatIntel:
    return ThreatIntel(POLICY.whitelist, BLACKLIST_TEXT)


# Alerta real: trafico interno h2 -> app:443, severidad 3
REAL_ALERT = ('{"timestamp":"2026-11-15T20:37:48.340946+0000","flow_id":1356245165387002,"in_iface":"ens4",'
              '"event_type":"alert","src_ip":"192.168.10.2","src_port":58938,"dest_ip":"192.168.10.10",'
              '"dest_port":443,"proto":"TCP","pkt_src":"gre tunnel","metadata":{"flowints":'
              '{"applayer.anomaly.count":1}},"alert":{"action":"allowed","gid":1,"signature_id":2260001,'
              '"rev":1,"signature":"SURICATA Applayer Wrong direction first Data","category":'
              '"Generic Protocol Command Decode","severity":3},"tunnel":{"src_ip":"10.254.31.1",'
              '"src_port":0,"dest_ip":"10.254.31.2","dest_port":0,"proto":"GRE","depth":1,'
              '"pkt_src":"wire/pcap"},"app_proto":"failed","app_proto_tc":"tls","direction":"to_server"}')

# Evento HTTP real: h3 -> LMS:8080
REAL_HTTP = ('{"timestamp":"2026-11-17T16:21:37.986856+0000","flow_id":539017571620089,"in_iface":"ens4",'
             '"event_type":"http","src_ip":"192.168.10.3","src_port":53953,"dest_ip":"192.168.10.101",'
             '"dest_port":8080,"proto":"TCP","pkt_src":"gre tunnel","tx_id":0,"http":{"hostname":'
             '"192.168.10.101","http_port":8080,"url":"/g2-normal","http_content_type":"application/json",'
             '"http_method":"GET","protocol":"HTTP/1.1","status":200,"length":52}}')

# Evento TLS real: h2 -> app:443 (sin SNI)
REAL_TLS = ('{"timestamp":"2026-11-15T18:02:52.184351+0000","flow_id":1248305631411111,"in_iface":"ens4",'
            '"event_type":"tls","src_ip":"192.168.10.2","src_port":49892,"dest_ip":"192.168.10.10",'
            '"dest_port":443,"proto":"TCP","pkt_src":"gre tunnel","tls":{"version":"TLS 1.3"}}')


def ts(second: int = 0, minute: int = 0) -> str:
    return f"2026-11-19T19:{minute:02d}:{second:02d}.000000+0000"


def alert_line(src="203.0.113.2", dst="192.168.10.101", sid=9000001, severity=1,
               when=None, signature="SINTETICO prueba perimetral", sport=40000, dport=8080,
               proto="TCP", **extra) -> str:
    event = {
        "timestamp": when or ts(), "flow_id": 1000 + sid, "in_iface": "ens6", "event_type": "alert",
        "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": proto,
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                  "signature": signature, "category": "Prueba", "severity": severity},
    }
    event.update(extra)
    return json.dumps(event)


def dns_answer_line(rrname, answers=(), src="8.8.4.4", dst="192.168.10.1", when=None,
                    grouped=None) -> str:
    dns = {"version": 2, "type": "answer", "id": 4242, "rrname": rrname, "rrtype": "A",
           "rcode": "NOERROR",
           "answers": [{"rrname": rrname, "rrtype": "A", "ttl": 300, "rdata": ip} for ip in answers]}
    if grouped is not None:
        dns["grouped"] = grouped
    return json.dumps({"timestamp": when or ts(), "flow_id": 77, "in_iface": "ens6",
                       "event_type": "dns", "src_ip": src, "src_port": 53, "dest_ip": dst,
                       "dest_port": 51515, "proto": "UDP", "dns": dns})


def tls_line(sni, src="192.168.10.1", dst="198.51.100.77", when=None) -> str:
    return json.dumps({"timestamp": when or ts(), "flow_id": 88, "in_iface": "ens6",
                       "event_type": "tls", "src_ip": src, "src_port": 50000, "dest_ip": dst,
                       "dest_port": 443, "proto": "TCP", "tls": {"sni": sni, "version": "TLS 1.3"}})


class FakeBackend:
    """Sustituto de Floodlight para las pruebas: guarda las reglas en memoria."""

    def __init__(self):
        self.rules = {}
        self.removed = []

    def existing_rule_names(self):
        return set(self.rules)

    def install(self, rule):
        self.rules[rule["name"]] = rule

    def remove(self, name):
        self.rules.pop(name, None)
        self.removed.append(name)
