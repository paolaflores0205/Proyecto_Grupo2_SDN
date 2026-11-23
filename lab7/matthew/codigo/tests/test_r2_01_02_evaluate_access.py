"""R2-01 y R2-02: evaluate_access, matriz real de 4 roles, separacion DTI y adaptador SQL."""
import unittest

from access import (
    DTIAccount,
    Decision,
    evaluate_access,
    evaluate_dti_console_access,
    load_access_matrix_from_rows,
)

from .access_helpers import make_matrix


class EvaluateAccess(unittest.TestCase):
    def test_2_1_1_admin_permit_teacher_deny_and_dti_separation(self):
        """2.1.1 Normal / invalido (R2-01): DTI permitido en consola_dti; docente y administrativo denegados."""
        m = make_matrix()
        admin = evaluate_access(m, "Administrador DTI", "consola_dti")
        docente = evaluate_access(m, "docente", "consola_dti")
        administrativo_dti = evaluate_access(m, "administrativo", "consola_dti")
        administrativo_acad = evaluate_access(m, "administrativo", "administracion")

        self.assertEqual(admin.decision, Decision.PERMIT)
        self.assertEqual(docente.decision, Decision.DENY)
        self.assertIn("recurso critico", docente.reason)
        # Separacion estricta: rol 'administrativo' accede a 'administracion' (h4:8443), NO a consola_dti
        self.assertEqual(administrativo_acad.decision, Decision.PERMIT)
        self.assertEqual(administrativo_dti.decision, Decision.DENY)

    def test_2_1_2_unknown_role_or_resource_denied(self):
        """2.1.2 Limite (R2-02): rol inexistente o recurso fuera de inventario -> DENY por defecto."""
        m = make_matrix()
        invitado = evaluate_access(m, "Invitado", "lms")
        fuera = evaluate_access(m, "docente", "servidor_x")
        self.assertEqual((invitado.decision, invitado.reason), (Decision.DENY, "Rol no registrado"))
        self.assertEqual((fuera.decision, fuera.reason), (Decision.DENY, "Recurso fuera del inventario"))

    def test_2_1_3_explicit_deny_beats_permit_in_matrix(self):
        """2.1.3 Normal (R2-01): si la matriz contiene PERMIT y DENY para el mismo par, gana DENY."""
        m = make_matrix(extra_permissions=[("docente", "notas", False)])
        result = evaluate_access(m, "docente", "notas")
        self.assertEqual((result.decision, result.reason), (Decision.DENY, "Denegado explicitamente en la matriz"))

    def test_2_1_4_full_four_role_matrix(self):
        """2.1.4 Normal (R2-01/R2-02): matriz completa de 4 roles de campus x 4 recursos."""
        m = make_matrix()
        expected = {
            "estudiante": {"lms": Decision.PERMIT, "notas": Decision.DENY, "administracion": Decision.DENY, "consola_dti": Decision.DENY},
            "docente": {"lms": Decision.PERMIT, "notas": Decision.PERMIT, "administracion": Decision.DENY, "consola_dti": Decision.DENY},
            "administrativo": {"lms": Decision.DENY, "notas": Decision.DENY, "administracion": Decision.PERMIT, "consola_dti": Decision.DENY},
            "visitante": {"lms": Decision.DENY, "notas": Decision.DENY, "administracion": Decision.DENY, "consola_dti": Decision.DENY},
        }
        for role, targets in expected.items():
            for res, exp_dec in targets.items():
                with self.subTest(role=role, resource=res):
                    self.assertEqual(evaluate_access(m, role, res).decision, exp_dec)

    def test_2_1_5_dti_console_identity_and_authorized_binding(self):
        """2.1.5 Integracion simulada (R2-01): consola DTI vinculada a admin_accounts y red de gestion."""
        dti_ok = DTIAccount(admin_id=1, username="dti_admin", active=True, source_ip="192.168.0.1")
        dti_off = DTIAccount(admin_id=2, username="dti_baja", active=False, source_ip="192.168.0.1")

        self.assertEqual(evaluate_dti_console_access(dti_ok, "192.168.0.1").decision, Decision.PERMIT)
        # Desde red de datos (h1=192.168.10.1) siempre DENY aunque exista cuenta
        self.assertEqual(evaluate_dti_console_access(dti_ok, "192.168.10.1").decision, Decision.DENY)
        # Sin sesion en admin_accounts o cuenta inactiva o IP distinta -> DENY
        self.assertEqual(evaluate_dti_console_access(None, "192.168.0.1").decision, Decision.DENY)
        self.assertEqual(evaluate_dti_console_access(dti_off, "192.168.0.1").decision, Decision.DENY)
        self.assertEqual(evaluate_dti_console_access(dti_ok, "192.168.0.50").decision, Decision.DENY)

    def test_2_1_6_load_access_matrix_from_sql_rows(self):
        """2.1.6 Integracion simulada (R2-01/R2-02): construccion de AccessMatrix desde filas role_permissions."""
        rows = [
            {"role_code": "docente", "code": "lms", "allowed": 1, "deployment_state": "active", "transport": "TCP", "ip_address": "192.168.10.101", "port": 443, "privileged": 0},
            {"role_code": "docente", "code": "notas", "allowed": 1, "deployment_state": "active", "transport": "TCP", "ip_address": "192.168.10.102", "port": 443, "privileged": 1},
            {"role_code": "docente", "code": "administracion", "allowed": 0, "deployment_state": "active", "transport": "TCP", "ip_address": "192.168.10.102", "port": 8443, "privileged": 1},
            {"role_code": "estudiante", "code": "notas", "allowed": 1, "deployment_state": "disabled", "transport": "TCP", "ip_address": "192.168.10.102", "port": 443, "privileged": 1},
        ]
        matrix = load_access_matrix_from_rows(rows)
        self.assertEqual(evaluate_access(matrix, "docente", "notas").decision, Decision.PERMIT)
        self.assertEqual(evaluate_access(matrix, "docente", "administracion").decision, Decision.DENY)
        # Recurso con deployment_state != 'active' resulta DENY
        self.assertEqual(evaluate_access(matrix, "estudiante", "notas").decision, Decision.DENY)
        # Rol de campus nunca accede a consola_dti
        self.assertEqual(evaluate_access(matrix, "docente", "consola_dti").decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
