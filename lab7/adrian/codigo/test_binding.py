import unittest

from r3 import check_binding
from r5 import Rejected


class BindingTests(unittest.TestCase):
    lease = {"ingress_port": 5, "ip": "192.0.2.10", "mac": "02:00:00:00:00:10"}

    def observe(self, **changes):
        observation = {
            "observed_ip": self.lease["ip"],
            "observed_mac": self.lease["mac"],
            "observed_port": self.lease["ingress_port"],
        }
        return check_binding(lease=self.lease, **{**observation, **changes})

    def test_correct_binding(self):
        self.assertTrue(self.observe()["valid"])

    def test_wrong_ip(self):
        self.assertFalse(self.observe(observed_ip="192.0.2.20")["valid"])

    def test_wrong_mac(self):
        result = self.observe(observed_mac="02:00:00:00:00:20")
        self.assertFalse(result["valid"])
        self.assertEqual(result["offending_port"], 5)

    def test_wrong_port(self):
        with self.assertRaisesRegex(Rejected, "no corresponde al puerto"):
            self.observe(observed_port=4)

    def test_unknown_port_is_not_verifiable(self):
        with self.assertRaisesRegex(Rejected, "Falta el puerto real"):
            self.observe(observed_port=None)


if __name__ == "__main__":
    unittest.main()
