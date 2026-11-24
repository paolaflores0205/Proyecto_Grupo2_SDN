"""Integracion sin red real: un Floodlight simulado por HTTP y el servicio sdn-r5 de punta a punta."""
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from r5.engine import Engine
from r5.floodlight import FloodlightBackend, FloodlightError
from r5.service import R5Service, make_admin_handler, make_event_handler

from .helpers import POLICY, alert_line, make_intel
from .test_engine import Clock

EDGE = "00:00:00:00:00:00:00:05"


class FakeFloodlight(BaseHTTPRequestHandler):
    """Imita las rutas del Static Flow Pusher que usa el modulo."""
    store = {}

    def log_message(self, *args):
        pass

    def _send(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

    def do_GET(self):
        if self.path == f"/wm/staticflowpusher/list/{EDGE}/json":
            return self._send({EDGE: [{n: {"match": {}}} for n in self.store]})
        if self.path == "/wm/core/controller/switches/json":
            return self._send([{"switchDPID": EDGE}])
        self._send({}, 404)

    def do_POST(self):
        rule = self._body()
        self.store[rule["name"]] = rule
        self._send({"status": "Entry pushed"})

    def do_DELETE(self):
        self.store.pop(self._body()["name"], None)
        self._send({"status": "Entry " + "deleted"})


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def call(url, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


class FloodlightBackendTests(unittest.TestCase):
    def setUp(self):
        FakeFloodlight.store = {"g2-mt-base-x": {}, "g2-p03-r5-abc": {}}
        self.fl = serve(FakeFloodlight)
        self.backend = FloodlightBackend(f"http://127.0.0.1:{self.fl.server_port}", EDGE, "g2-r5")

    def tearDown(self):
        self.fl.shutdown()
        self.fl.server_close()

    def test_5_10_1_install_list_remove(self):
        """5.10.1 Integracion: instala, lista solo las reglas propias y las quita por nombre."""
        self.backend.install({"name": "g2-r5-203-0-113-2-in", "switch": EDGE})
        self.assertEqual(self.backend.existing_rule_names(), {"g2-r5-203-0-113-2-in"})
        self.backend.remove("g2-r5-203-0-113-2-in")
        self.assertEqual(self.backend.existing_rule_names(), set())
        self.assertIn("g2-p03-r5-abc", FakeFloodlight.store)  # no toca reglas ajenas

    def test_5_10_2_unreachable_controller(self):
        """5.10.2 Contingencia: si Floodlight no responde se lanza FloodlightError, no un error generico."""
        dead = FloodlightBackend("http://127.0.0.1:9", EDGE, "g2-r5", timeout=1)
        with self.assertRaises(FloodlightError):
            dead.existing_rule_names()


class ServiceTests(unittest.TestCase):
    def setUp(self):
        FakeFloodlight.store = {}
        self.fl = serve(FakeFloodlight)
        backend = FloodlightBackend(f"http://127.0.0.1:{self.fl.server_port}", EDGE, "g2-r5")
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.blacklist = tmp / "blacklist.txt"
        self.blacklist.write_text("198.51.100.23\n", encoding="utf-8")
        incidents = tmp / "incidents.jsonl"
        engine = Engine(POLICY, make_intel(), backend, incident_path=str(incidents), clock=Clock())
        self.service = R5Service(engine, self.blacklist, incidents)
        self.events = serve(make_event_handler(self.service))
        self.admin = serve(make_admin_handler(self.service))
        self.ev = f"http://127.0.0.1:{self.events.server_port}"
        self.ad = f"http://127.0.0.1:{self.admin.server_port}"

    def tearDown(self):
        for srv in (self.events, self.admin, self.fl):
            srv.shutdown()
            srv.server_close()
        self.tmp.cleanup()

    def test_5_11_1_event_to_rule_end_to_end(self):
        """5.11.1 Integracion: un lote con una alerta grave termina en dos reglas en el Floodlight simulado."""
        reply = call(self.ev + "/r5/events", "POST", {"lines": ["{rota", alert_line(severity=1)]})
        self.assertEqual(reply["processed"], 2)
        self.assertEqual(sorted(FakeFloodlight.store), ["g2-r5-203-0-113-2-in", "g2-r5-203-0-113-2-out"])
        health = call(self.ad + "/r5/health")
        self.assertEqual((health["active_blocks"], health["floodlight"]["edge_connected"]), (1, True))
        self.assertEqual(len(call(self.ad + "/r5/incidents")), 1)

    def test_5_11_2_admin_unblock_and_feed_reload(self):
        """5.11.2 Normal: el desbloqueo manual y la recarga del feed funcionan por la API local."""
        call(self.ev + "/r5/events", "POST", {"lines": [alert_line(severity=1)]})
        out = call(self.ad + "/r5/blocks/203.0.113.2", "DELETE")
        self.assertEqual(len(out["removed"]), 2)
        self.assertEqual(call(self.ad + "/r5/blocks"), [])
        self.blacklist.write_text("203.0.113.66\nmalware.example\n", encoding="utf-8")
        report = call(self.ad + "/r5/feed/reload", "POST", {})
        self.assertIn("198.51.100.23/32", report["removed_networks"])
        self.assertEqual(report["added_networks"], [])

    def test_5_11_3_bad_requests(self):
        """5.11.3 Invalido: cuerpos mal formados y rutas desconocidas se rechazan con codigos HTTP claros."""
        for body, code in (({"otra": 1}, 400), ({"lines": "no-lista"}, 400)):
            with self.subTest(body=body):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    call(self.ev + "/r5/events", "POST", body)
                self.assertEqual(ctx.exception.code, code)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            call(self.ad + "/r5/nada")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
