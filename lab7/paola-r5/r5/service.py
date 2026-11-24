"""Servicio sdn-r5 (VM app): receptor de eventos con mTLS + API local de administracion.

  Receptor  https://<ip de gestion>:9450  (solo clientes con certificado de la CA de R5)
     POST /r5/events            {"lines": ["<linea eve.json>", ...]}
  Admin     http://127.0.0.1:9451   (solo desde la propia VM)
     GET    /r5/health
     GET    /r5/blocks
     DELETE /r5/blocks/<ip>
     POST   /r5/feed/reload     (relee el archivo de lista negra de la politica)
     GET    /r5/incidents?since=<ISO 8601>

Uso: python3 -m r5.service --config /etc/sdn-r5/service.json
"""
from __future__ import annotations

import argparse
import json
import ssl
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from .engine import Engine
from .floodlight import FloodlightBackend
from .intel import FeedRejected, ThreatIntel
from .policy import load_policy

MAX_BODY = 4 * 1024 * 1024
MAX_LINES = 5000


class R5Service:
    """Motor + candado + utilidades que comparten el receptor y la API de administracion."""

    def __init__(self, engine: Engine, blacklist_path: Optional[Path], incident_path: Optional[Path]):
        self.engine = engine
        self.blacklist_path = blacklist_path
        self.incident_path = incident_path
        self.lock = threading.Lock()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._last_brake_warning = 0.0

    def handle_lines(self, lines) -> dict:
        blocked, processed, throttled = [], 0, []
        rejected = {"stale": 0, "future": 0}
        duplicates = 0
        with self.lock:
            for line in lines[:MAX_LINES]:
                out = self.engine.process_line(line)
                processed += 1
                if out.rejected:
                    rejected[out.rejected] += 1
                duplicates += int(out.duplicate)
                blocked.extend(out.installed)
                throttled.extend(out.throttled)
            if throttled and time.monotonic() - self._last_brake_warning >= 60:
                # aviso en journald para el operador, como mucho uno por minuto
                self._last_brake_warning = time.monotonic()
                print(json.dumps({"status": "freno_activado", "detalle": self.engine.last_brake,
                                  "frenos": self.engine.brake_status()}, ensure_ascii=False), flush=True)
        return {"processed": processed, "installed": blocked, "throttled": throttled,
                "rejected": rejected, "duplicates": duplicates}

    def maintenance_once(self) -> dict:
        with self.lock:
            return self.engine.maintenance()

    def health(self) -> dict:
        with self.lock:
            stats = dict(self.engine.stats)
            active = len(self.engine.active_blocks())
            brakes = self.engine.brake_status()
        try:
            switches = self.engine.backend.connected_switches()  # type: ignore[attr-defined]
            floodlight = {"ok": True, "switches": len(switches),
                          "edge_connected": self.engine.policy.edge_dpid in switches}
        except Exception as exc:
            floodlight = {"ok": False, "error": str(exc)}
        return {"service": "sdn-r5", "started_at": self.started_at, "active_blocks": active,
                "floodlight": floodlight, "brakes": brakes, "stats": stats,
                "cleanup_errors": list(self.engine.cleanup_errors)}

    def blocks(self) -> list:
        with self.lock:
            return self.engine.active_blocks()

    def unblock(self, ip: str) -> dict:
        with self.lock:
            return {"ip": ip, "removed": self.engine.unblock(ip)}

    def reload_feed(self) -> dict:
        if self.blacklist_path is None:
            raise FeedRejected("La politica no define blacklist_file")
        text = self.blacklist_path.read_text(encoding="utf-8")
        with self.lock:
            r = self.engine.reload_feed(text)
        return {"added_networks": r.added_networks, "removed_networks": r.removed_networks,
                "added_domains": r.added_domains, "removed_domains": r.removed_domains,
                "ignored": [{"line": n, "text": t, "reason": why} for n, t, why in r.ignored]}

    def incidents(self, since: Optional[str]) -> list:
        if self.incident_path is None or not self.incident_path.exists():
            return []
        out = []
        for line in self.incident_path.read_text(encoding="utf-8").splitlines()[-2000:]:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since is None or (rec.get("decided_at") or "") >= since:
                out.append(rec)
        return out


def _json(handler: BaseHTTPRequestHandler, status: int, payload) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def make_event_handler(service: R5Service):
    class EventHandler(BaseHTTPRequestHandler):
        server_version = "sdn-r5"

        def log_message(self, fmt, *args):  # sin ruido en journald por cada lote
            pass

        def do_POST(self):
            if self.path != "/r5/events":
                return _json(self, 404, {"error": "ruta desconocida"})
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                return _json(self, 413, {"error": "cuerpo vacio o demasiado grande"})
            try:
                body = json.loads(self.rfile.read(length))
                lines = body["lines"]
                if not isinstance(lines, list):
                    raise TypeError
            except (json.JSONDecodeError, KeyError, TypeError):
                return _json(self, 400, {"error": "se espera {\"lines\": [...]}"})
            return _json(self, 200, service.handle_lines([str(x) for x in lines]))

    return EventHandler


def make_admin_handler(service: R5Service):
    class AdminHandler(BaseHTTPRequestHandler):
        server_version = "sdn-r5-admin"

        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/r5/health":
                return _json(self, 200, service.health())
            if url.path == "/r5/blocks":
                return _json(self, 200, service.blocks())
            if url.path == "/r5/incidents":
                since = parse_qs(url.query).get("since", [None])[0]
                return _json(self, 200, service.incidents(since))
            return _json(self, 404, {"error": "ruta desconocida"})

        def do_DELETE(self):
            if self.path.startswith("/r5/blocks/"):
                ip = unquote(self.path[len("/r5/blocks/"):])
                try:
                    return _json(self, 200, service.unblock(ip))
                except Exception as exc:
                    return _json(self, 502, {"error": str(exc)})
            return _json(self, 404, {"error": "ruta desconocida"})

        def do_POST(self):
            if self.path == "/r5/feed/reload":
                try:
                    return _json(self, 200, service.reload_feed())
                except FeedRejected as exc:
                    return _json(self, 422, {"error": str(exc)})
                except Exception as exc:
                    return _json(self, 502, {"error": str(exc)})
            return _json(self, 404, {"error": "ruta desconocida"})

    return AdminHandler


def server_tls_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # sin certificado de la CA de R5 no hay conexion
    return ctx


def build_service(config: dict) -> R5Service:
    policy_path = Path(config["policy"])
    policy = load_policy(policy_path)
    blacklist = (policy_path.parent / policy.blacklist_file) if policy.blacklist_file else None
    intel = ThreatIntel(policy.whitelist,
                        blacklist.read_text(encoding="utf-8") if blacklist and blacklist.exists() else (),
                        min_prefix_v4=policy.feed_min_prefix_v4, min_prefix_v6=policy.feed_min_prefix_v6)
    backend = FloodlightBackend(config.get("floodlight_url", "http://127.0.0.1:8080"),
                                policy.edge_dpid, policy.rule_prefix)
    incidents = Path(config.get("incident_log") or policy.incident_log or "incidents.jsonl")
    engine = Engine(policy, intel, backend, incident_path=str(incidents),
                    state_path=str(config.get("block_state") or incidents.with_name("r5-block-state.json")),
                    dedupe_seconds=(float(config["dedupe_seconds"]) if "dedupe_seconds" in config else None))
    # Fallar al arrancar si no se puede reconciliar: no se inventan plazos.
    recovered = engine.recover_blocks(backend.list_rules())
    if recovered:
        print(json.dumps({"status": "bloqueos_recuperados", "ips": recovered}), flush=True)
    return R5Service(engine, blacklist, incidents)


def maintenance_loop(service: R5Service, stop: threading.Event, interval: float = 1.0) -> None:
    """Limpieza periodica aun cuando no llegan eventos ni consultas al modulo."""
    while not stop.is_set():
        try:
            result = service.maintenance_once()
            if result["errors"]:
                print(json.dumps({"status": "limpieza_pendiente", **result}), flush=True)
        except Exception as exc:
            print(json.dumps({"status": "error_mantenimiento", "error": str(exc)}), flush=True)
        stop.wait(interval)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Servicio R5 de proteccion perimetral")
    parser.add_argument("--config", default="/etc/sdn-r5/service.json")
    args = parser.parse_args(argv)
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    service = build_service(config)

    events = ThreadingHTTPServer((config["listen_host"], int(config.get("listen_port", 9450))),
                                 make_event_handler(service))
    tls = config["tls"]
    events.socket = server_tls_context(tls["cert"], tls["key"], tls["ca"]).wrap_socket(
        events.socket, server_side=True)
    admin = ThreadingHTTPServer(("127.0.0.1", int(config.get("admin_port", 9451))),
                                make_admin_handler(service))
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    stop_maintenance = threading.Event()
    threading.Thread(target=maintenance_loop, args=(service, stop_maintenance), daemon=True).start()
    print(json.dumps({"status": "listening", "events": f"{config['listen_host']}:{events.server_port}",
                      "admin": f"127.0.0.1:{admin.server_port}"}), flush=True)
    events.serve_forever()


if __name__ == "__main__":
    main()
