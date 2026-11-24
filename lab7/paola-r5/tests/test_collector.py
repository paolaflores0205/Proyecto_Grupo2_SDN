"""Colector: filtro de eventos, cursor persistente, rotacion del log y reintentos."""
import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path

from collector.collector import Cursor, is_relevant, run_once

from .helpers import REAL_ALERT, REAL_HTTP, alert_line

INTERNAL = [ipaddress.ip_network("192.168.10.0/24"), ipaddress.ip_network("192.168.0.0/24")]
STATS = json.dumps({"timestamp": "2026-11-19T19:00:00+0000", "event_type": "stats", "stats": {}})


class Filter(unittest.TestCase):
    def test_5_12_1_only_useful_perimeter_events(self):
        """5.12.1 Normal: pasan alertas con extremo externo; no pasan internas, stats ni lineas rotas."""
        self.assertTrue(is_relevant(alert_line(), INTERNAL))
        for line in (REAL_ALERT, REAL_HTTP, STATS, "{rota", ""):
            with self.subTest(line=line[:30]):
                self.assertFalse(is_relevant(line, INTERNAL))


class CursorAndDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.eve, self.state = d / "eve.json", d / "cursor.json"
        self.sent = []

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, *lines, mode="a"):
        with self.eve.open(mode, encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    def send(self, lines):
        self.sent.extend(lines)
        return {"processed": len(lines)}

    def test_5_12_2_starts_at_end_then_follows(self):
        """5.12.2 Normal: no reenvia la historia al arrancar; despues envia solo lo nuevo y util."""
        self.write(alert_line(sid=1))
        cursor = Cursor(self.state)
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.assertEqual(self.sent, [])
        self.write(alert_line(sid=2), REAL_ALERT, STATS)
        r = run_once(self.eve, Cursor(self.state), INTERNAL, self.send)  # cursor releido del disco
        self.assertEqual((r["read"], r["sent"]), (3, 1))
        self.assertIn('"signature_id": 2', self.sent[0])

    def test_5_12_3_rotation_and_truncation(self):
        """5.12.3 Limite: tras copytruncate (archivo mas corto) vuelve a leer desde el inicio."""
        self.write(alert_line(sid=1), alert_line(sid=2))
        cursor = Cursor(self.state)
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.write(alert_line(sid=3), mode="w")  # truncado por logrotate y nueva linea
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.assertEqual(len(self.sent), 1)
        self.assertIn('"signature_id": 3', self.sent[0])

    def test_5_12_4_failed_delivery_does_not_lose_events(self):
        """5.12.4 Contingencia: si el receptor falla, el cursor no avanza y el evento se reenvia despues."""
        self.write(alert_line(sid=1))
        cursor = Cursor(self.state)
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.write(alert_line(sid=9))

        def broken(lines):
            raise ConnectionError("receptor caido")

        with self.assertRaises(ConnectionError):
            run_once(self.eve, cursor, INTERNAL, broken)
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.assertEqual(len(self.sent), 1)
        self.assertIn('"signature_id": 9', self.sent[0])

    def test_5_12_5_partial_line_waits(self):
        """5.12.5 Limite: una linea a medio escribir no se envia hasta que termina."""
        self.write(alert_line(sid=1))
        cursor = Cursor(self.state)
        run_once(self.eve, cursor, INTERNAL, self.send)
        with self.eve.open("a", encoding="utf-8") as fh:
            fh.write(alert_line(sid=5)[:40])
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.assertEqual(self.sent, [])
        with self.eve.open("a", encoding="utf-8") as fh:
            fh.write(alert_line(sid=5)[40:] + "\n")
        run_once(self.eve, cursor, INTERNAL, self.send)
        self.assertEqual(len(self.sent), 1)


if __name__ == "__main__":
    unittest.main()
