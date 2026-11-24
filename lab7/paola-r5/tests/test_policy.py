"""load_policy: el modulo no arranca con una politica invalida."""
import json
import unittest

from r5 import PolicyError, load_policy

from .helpers import ROOT


def base():
    return json.loads((ROOT / "config" / "policy.json").read_text(encoding="utf-8"))


class PolicyValidation(unittest.TestCase):
    def test_5_9_1_repo_policy_is_valid(self):
        """5.9.1 Normal: la politica del repo carga y conoce redes internas y lista blanca."""
        p = load_policy(ROOT / "config" / "policy.json")
        self.assertEqual((p.edge_dpid, p.edge_port, p.priority), ("00:00:00:00:00:00:00:05", 3, 32000))
        self.assertTrue(p.is_internal("192.168.10.101"))
        self.assertFalse(p.is_internal("203.0.113.2"))
        self.assertTrue(p.is_whitelisted("192.168.3.31"))

    def test_5_9_2_invalid_policies_rejected(self):
        """5.9.2 Invalido: DPID, prioridad, duraciones o redes erroneas se rechazan con PolicyError."""
        mutations = {
            "dpid": lambda r: r["edge"].update(switch_dpid="05"),
            "priority": lambda r: r.update(priority=70000),
            "max<base": lambda r: r["durations"].update(max_seconds=10),
            "network": lambda r: r.update(whitelist=["no-es-red"]),
            "version": lambda r: r.update(schema_version=2),
            "prefix": lambda r: r.update(rule_prefix="G2 R5!"),
            "no internal": lambda r: r.update(internal_networks=[]),
            "override sev": lambda r: r.update(severity_overrides={"2013031": 7}),
            "override sid": lambda r: r.update(severity_overrides={"abc": 3}),
        }
        for label, mutate in mutations.items():
            raw = base()
            mutate(raw)
            with self.subTest(case=label):
                with self.assertRaises(PolicyError):
                    load_policy(raw)

    def test_5_9_3_missing_file(self):
        """5.9.3 Invalido: un archivo inexistente da PolicyError, no un error generico."""
        with self.assertRaises(PolicyError):
            load_policy(ROOT / "config" / "no-existe.json")


if __name__ == "__main__":
    unittest.main()
