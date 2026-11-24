"""R5-06 update_blacklist: entradas validas, entradas con errores y entradas retiradas."""
import unittest

from r5 import FeedRejected

from .helpers import make_intel

NEW_FEED = """\
# version 2 del feed
203.0.113.66
198.51.100.0/24
esto-no-es-valido!!
300.300.300.300
8.8.4.4                # en la lista blanca: debe ignorarse
nuevo-c2.example
malware.example
"""


class UpdateBlacklist(unittest.TestCase):
    def test_5_6_1_valid_errors_and_removed(self):
        """5.6.1 Limite: entran las validas, se ignoran las erroneas y la retirada deja de bloquearse."""
        intel = make_intel()
        self.assertTrue(intel.is_malicious_ip("203.0.113.130"))  # antes: en 203.0.113.128/26
        report = intel.update_blacklist(NEW_FEED)
        self.assertEqual(report.added_networks, ["198.51.100.0/24"])
        self.assertIn("203.0.113.128/26", report.removed_networks)
        self.assertEqual(report.added_domains, ["nuevo-c2.example"])
        self.assertEqual(sorted(report.removed_domains), ["c2.test", "phishing.example.net"])
        ignored = {(line, text) for line, text, _ in report.ignored}
        self.assertEqual(ignored, {(4, "esto-no-es-valido!!"), (5, "300.300.300.300"), (6, "8.8.4.4")})
        self.assertFalse(intel.is_malicious_ip("203.0.113.130"))  # retirada
        self.assertTrue(intel.is_malicious_ip("198.51.100.200"))  # nueva red
        self.assertFalse(intel.is_malicious_ip("8.8.4.4"))
        self.assertFalse(intel.is_malicious_domain("c2.test"))

    def test_5_6_2_empty_feed_keeps_previous_list(self):
        """5.6.2 Limite: un feed vacio, solo con comentarios o sin entradas validas no borra la lista."""
        intel = make_intel()
        for feed in ("", "# solo comentarios\n\n", "basura!!\n???", []):
            with self.subTest(feed=feed):
                with self.assertRaises(FeedRejected):
                    intel.update_blacklist(feed)
                self.assertTrue(intel.is_malicious_ip("203.0.113.66"))
                self.assertTrue(intel.is_malicious_domain("c2.test"))

    def test_5_6_3_accepts_list_of_lines(self):
        """5.6.3 Normal: el feed tambien puede venir como lista de lineas."""
        intel = make_intel()
        intel.update_blacklist(["203.0.113.99", "evil.example"])
        self.assertTrue(intel.is_malicious_ip("203.0.113.99"))
        self.assertFalse(intel.is_malicious_ip("203.0.113.66"))


if __name__ == "__main__":
    unittest.main()
