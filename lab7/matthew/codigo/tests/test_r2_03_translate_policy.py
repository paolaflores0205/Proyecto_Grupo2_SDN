"""R2-03: traduccion de politicas al pipeline multitabla real (sw2 0/10/20/30 + transito sw1/sw4/sw3)."""
import unittest

from access import (
    DENY_PRIORITY,
    Decision,
    PolicyEntry,
    effective_table20_decision,
    session_context,
    translate_policy,
)
from access.translate import DPIDS, LMS_BIT

from .access_helpers import ADMINISTRACION, CONSOLA_DTI, H1, H2, LMS, NOTAS


class TranslatePolicyMultitable(unittest.TestCase):
    def test_2_2_1_deny_wins_over_permit_in_sw2_table20(self):
        """2.2.1 Normal (R2-03): con PERMIT y DENY solapados en sw2 tabla 20, prevalece DENY (prio 550 > 501)."""
        flows = translate_policy(
            [PolicyEntry("docente", NOTAS, Decision.PERMIT), PolicyEntry("docente", NOTAS, Decision.DENY)],
            H2,
            session_id="sess_r2_03_overlap",
            generation=1,
            emit_overlapped_permit=True,
        )
        t20 = [f for f in flows if f["switch"] == DPIDS["sw2"] and f["table"] == "20"]
        permits = [f for f in t20 if "-grant-" in f["name"]]
        denies = [f for f in t20 if "-deny-" in f["name"]]
        self.assertEqual(len(permits), 2)  # ida y retorno
        self.assertEqual(len(denies), 2)   # ida y retorno
        for f in permits:
            self.assertEqual(f["priority"], "501")
            self.assertEqual(f["instruction_goto_table"], "30")
        for f in denies:
            self.assertEqual(f["priority"], str(DENY_PRIORITY))  # 550
            self.assertEqual(f["actions"], "")
            self.assertNotIn("instruction_goto_table", f)

        # Resolucion efectiva de tabla 20: ambos sentidos (ida y retorno) terminan en DENY
        eff = effective_table20_decision(flows)
        self.assertEqual(len(eff), 2)
        self.assertTrue(all(d is Decision.DENY for d in eff.values()))
        # Ninguna regla de transito en sw1/sw3 fue emitida porque la decision efectiva es DENY
        transit = [f for f in flows if f["switch"] != DPIDS["sw2"]]
        self.assertEqual(transit, [])

    def test_2_2_2_multitable_pipeline_matches_exact_session(self):
        """2.2.2 Normal (R2-03): PERMIT genera tablas 10/20/30 en sw2 + transito sw1/sw3 sin atajos en tabla 0."""
        flows = translate_policy(
            [PolicyEntry("docente", LMS, Decision.PERMIT), PolicyEntry("docente", NOTAS, Decision.PERMIT)],
            H2,
            session_id="sess_docente_h2",
            seconds=30,
            generation=1,
            core_switch="sw1",
        )
        sw2_flows = [f for f in flows if f["switch"] == DPIDS["sw2"]]
        # Nunca se abren atajos en tabla 0 de sw2
        self.assertEqual([f for f in sw2_flows if f["table"] == "0"], [])
        t10 = [f for f in sw2_flows if f["table"] == "10"]
        t20 = [f for f in sw2_flows if f["table"] == "20"]
        t30 = [f for f in sw2_flows if f["table"] == "30"]
        self.assertEqual(len(t10), 2)  # class-0 y class-1
        self.assertEqual(len(t20), 2)  # notas ida y retorno (LMS va por metadata LMS_BIT)
        self.assertEqual(len(t30), 2)  # route-0 y route-1

        # Verificar bit LMS encendido en metadata de tabla 10
        expected_ctx = session_context("sess_docente_h2", "docente", lms_allowed=True)
        self.assertTrue(expected_ctx & LMS_BIT)
        ida_t10 = [f for f in t10 if f["name"].endswith("-class-0-renew-1")][0]
        self.assertEqual(ida_t10["in_port"], "4")
        self.assertEqual(ida_t10["eth_src"], H2.mac)
        self.assertEqual(ida_t10["ipv4_src"], "192.168.10.2/32")
        self.assertEqual(ida_t10["instruction_write_metadata"], hex(expected_ctx | 0))
        self.assertEqual(ida_t10["instruction_goto_table"], "20")

        # Verificar transito ida/retorno en sw1 y sw3 para notas (4 reglas)
        sw1_flows = [f for f in flows if f["switch"] == DPIDS["sw1"]]
        sw3_flows = [f for f in flows if f["switch"] == DPIDS["sw3"]]
        self.assertEqual(len(sw1_flows), 2)
        self.assertEqual(len(sw3_flows), 2)
        self.assertTrue(all(f["hard_timeout"] == "30" for f in flows))

    def test_2_2_3_duplicates_invalid_decisions_and_management_isolation(self):
        """2.2.3 Limite / invalido (R2-03): sin duplicados, decision invalida rechazada y consola_dti sin flujos."""
        same = PolicyEntry("administrativo", ADMINISTRACION, Decision.PERMIT)
        flows = translate_policy([same, same, PolicyEntry("administrativo", CONSOLA_DTI, Decision.PERMIT)], H1)
        names = [f["name"] for f in flows]
        self.assertEqual(len(names), len(set(names)))
        # Nunca se generan flujos de plano de datos para consola_dti (plane='management')
        self.assertFalse(any("consola_dti" in n for n in names))
        with self.assertRaises(ValueError):
            translate_policy([PolicyEntry("estudiante", LMS, "ALLOW")], H2)

    def test_2_2_4_lms_explicit_deny_clears_lms_bit_and_blocks_shared_rule(self):
        """2.2.4 Limite (R2-03): DENY explicito sobre LMS apaga LMS_BIT y gana sobre lms-shared-sw2 (prio 400)."""
        flows = translate_policy(
            [PolicyEntry("estudiante", LMS, Decision.PERMIT), PolicyEntry("estudiante", LMS, Decision.DENY)],
            H1,
            session_id="sess_lms_deny",
            emit_overlapped_permit=True,
        )
        t10_ida = [f for f in flows if f["table"] == "10" and "-class-0-" in f["name"]][0]
        written_md = int(t10_ida["instruction_write_metadata"], 16)
        self.assertEqual(written_md & LMS_BIT, 0)
        eff = effective_table20_decision(flows)
        self.assertTrue(all(d is Decision.DENY for d in eff.values()))

    def test_2_2_5_renewal_and_failover_sw4_preserve_deny_precedence(self):
        """2.2.5 Integracion simulada (R2-03): renovacion gen 1->0 (501->500) y failover sw4 conservan DENY."""
        gen1 = translate_policy(
            [PolicyEntry("docente", NOTAS, Decision.PERMIT), PolicyEntry("docente", NOTAS, Decision.DENY)],
            H2,
            session_id="sess_renew",
            generation=1,
            core_switch="sw4",
            emit_overlapped_permit=True,
        )
        gen0 = translate_policy(
            [PolicyEntry("docente", NOTAS, Decision.PERMIT), PolicyEntry("docente", NOTAS, Decision.DENY)],
            H2,
            session_id="sess_renew",
            generation=0,
            core_switch="sw4",
            emit_overlapped_permit=True,
        )
        # Aun combinando ambas generaciones durante el solapamiento de renovacion, DENY (550) gana siempre
        eff = effective_table20_decision(gen1 + gen0)
        self.assertTrue(all(d is Decision.DENY for d in eff.values()))

        # En PERMIT puro con failover a sw4, el transito se instala en sw4 y no en sw1
        ok_sw4 = translate_policy([PolicyEntry("docente", NOTAS, Decision.PERMIT)], H2, core_switch="sw4")
        self.assertEqual(len([f for f in ok_sw4 if f["switch"] == DPIDS["sw4"]]), 2)
        self.assertEqual(len([f for f in ok_sw4 if f["switch"] == DPIDS["sw1"]]), 0)


if __name__ == "__main__":
    unittest.main()
