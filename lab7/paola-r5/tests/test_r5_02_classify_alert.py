"""R5-02 classify_alert: la severidad y las listas deciden la accion."""
import unittest

from r5 import Action, RepeatTracker, classify_alert, parse_ids_alert

from .helpers import POLICY, REAL_ALERT, REAL_TLS, alert_line, make_intel, ts


def classify(line, tracker=None, intel=None):
    return classify_alert(parse_ids_alert(line), intel or make_intel(), POLICY, tracker)


class SeverityPolicy(unittest.TestCase):
    def test_5_2_1_high_severity_blocks(self):
        """5.2.1 Normal: severidad 1 desde el exterior bloquea la IP externa 300 s."""
        d = classify(alert_line(severity=1))
        self.assertEqual(d.action, Action.BLOCK)
        self.assertEqual(d.block_ips, ("203.0.113.2",))
        self.assertEqual(d.duration, 300)
        self.assertEqual(d.policy_rule, 4)

    def test_5_2_2_medium_and_low_are_not_blocked(self):
        """5.2.2 Normal: severidad 2 queda en vigilancia; severidad 3 y desconocida solo se registran."""
        self.assertEqual(classify(alert_line(severity=2)).action, Action.WATCH)
        self.assertEqual(classify(alert_line(severity=3)).action, Action.LOG)
        self.assertEqual(classify(alert_line(severity=9)).action, Action.LOG)  # severidad invalida -> None

    def test_5_2_3_medium_threshold(self):
        """5.2.3 Limite: 2 alertas medias en 60 s vigilan; la 3.a bloquea."""
        tracker = RepeatTracker(POLICY)
        actions = [classify(alert_line(severity=2, when=ts(s)), tracker).action for s in (0, 20, 40)]
        self.assertEqual(actions, [Action.WATCH, Action.WATCH, Action.BLOCK])

    def test_5_2_4_medium_spread_out_is_false_positive(self):
        """5.2.4 Falso positivo: 3 alertas medias separadas mas de 60 s no bloquean."""
        tracker = RepeatTracker(POLICY)
        whens = [ts(0, 0), ts(1, 1), ts(2, 2)]  # 19:00:00, 19:01:01, 19:02:02
        actions = [classify(alert_line(severity=2, when=w), tracker).action for w in whens]
        self.assertEqual(actions, [Action.WATCH] * 3)

    def test_5_2_5_repeat_offender_escalates(self):
        """5.2.5 Limite: cada reincidencia duplica el bloqueo hasta el tope de 3600 s."""
        tracker = RepeatTracker(POLICY)
        durations = [classify(alert_line(severity=1, when=ts(i)), tracker).duration for i in range(6)]
        self.assertEqual(durations, [300, 600, 1200, 2400, 3600, 3600])


class ListsAndScope(unittest.TestCase):
    def test_5_2_6_blacklist_overrides_low_severity(self):
        """5.2.6 Normal: una IP de la lista negra se bloquea aunque la alerta sea de severidad 3."""
        d = classify(alert_line(src="203.0.113.66", severity=3))
        self.assertEqual((d.action, d.policy_rule, d.duration), (Action.BLOCK, 2, 3600))

    def test_5_2_7_whitelist_never_blocked(self):
        """5.2.7 Falso positivo: una alerta grave desde una IP de la lista blanca solo se registra."""
        d = classify(alert_line(src="8.8.4.4", severity=1))
        self.assertEqual((d.action, d.policy_rule), (Action.LOG, 1))

    def test_5_2_8_internal_traffic_out_of_scope(self):
        """5.2.8 Limite: una alerta real entre hosts internos no la bloquea R5 (es de R3)."""
        d = classify(REAL_ALERT)
        self.assertEqual((d.action, d.policy_rule), (Action.LOG, 0))

    def test_5_2_10_calibrated_signature_only_logged(self):
        """5.2.10 Falso positivo: una firma calibrada por la linea base (Python-urllib, sid 2013031) solo se registra."""
        tracker = RepeatTracker(POLICY)
        actions = [classify(alert_line(sid=2013031, severity=2, when=ts(s)), tracker).action for s in (0, 1, 41)]
        self.assertEqual(actions, [Action.LOG] * 3)  # sin calibrar, la 3.a habria bloqueado
        self.assertEqual(classify(alert_line(sid=2049400, severity=2)).action, Action.WATCH)  # las demas no cambian

    def test_5_2_9_benign_protocol_event_ignored(self):
        """5.2.9 Normal: un evento TLS sin indicadores no genera incidente."""
        intel = make_intel()
        d = classify_alert(parse_ids_alert(REAL_TLS.replace("192.168.10.10", "93.184.216.34")),
                           intel, POLICY)
        self.assertEqual(d.action, Action.IGNORE)


if __name__ == "__main__":
    unittest.main()
