"""log_incident: registro con fecha, tipo, origen, destino y accion (R3-06 / documentacion de R5)."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from r5 import Action, classify_alert, log_incident, parse_ids_alert

from .helpers import POLICY, alert_line, make_intel


class IncidentLog(unittest.TestCase):
    def setUp(self):
        self.alert = parse_ids_alert(alert_line(severity=1, signature="SINTETICO escaneo"))
        self.decision = classify_alert(self.alert, make_intel(), POLICY)

    def test_5_7_1_record_fields_and_times(self):
        """5.7.1 Normal: el registro trae origen, destino, firma, accion y las tres marcas de tiempo."""
        decided = self.alert.timestamp + timedelta(milliseconds=850)
        installed = decided + timedelta(milliseconds=120)
        rec = log_incident(self.alert, self.decision, [{"name": "r1"}, {"name": "r2"}],
                           decided_at=decided, installed_at=installed)
        self.assertEqual((rec["src_ip"], rec["dest_ip"], rec["dest_port"]), ("203.0.113.2", "192.168.10.101", 8080))
        self.assertEqual((rec["action"], rec["policy_rule"], rec["duration_s"]), ("BLOCK", 4, 300))
        self.assertEqual(rec["signature"], "SINTETICO escaneo")
        self.assertEqual(rec["rules"], ["r1", "r2"])
        self.assertEqual(rec["detection_to_decision_ms"], 850.0)
        self.assertEqual(rec["decision_to_install_ms"], 120.0)
        self.assertEqual(rec["event_at"], "2026-11-19T19:00:00+00:00")
        self.assertEqual(len(rec["incident_id"]), 16)

    def test_5_7_2_appends_jsonl(self):
        """5.7.2 Normal: cada incidente se agrega como una linea JSON en el archivo (crea la carpeta)."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "incidents.jsonl"
            log_incident(self.alert, self.decision, path=path)
            log_incident(self.alert, self.decision, path=path)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["action"], "BLOCK")

    def test_5_7_3_non_block_has_no_install_time(self):
        """5.7.3 Limite: un incidente solo registrado no tiene hora de instalacion ni duracion."""
        low = parse_ids_alert(alert_line(severity=3))
        rec = log_incident(low, classify_alert(low, make_intel(), POLICY),
                           decided_at=datetime(2026, 11, 19, 19, 0, 1, tzinfo=timezone.utc))
        self.assertEqual(rec["action"], Action.LOG.value)
        self.assertIsNone(rec["installed_at"])
        self.assertIsNone(rec["decision_to_install_ms"])
        self.assertEqual(rec["duration_s"], 0)


if __name__ == "__main__":
    unittest.main()
