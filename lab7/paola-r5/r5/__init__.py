"""Modulo R5 del G2: proteccion perimetral (IPS logico sobre Suricata + OpenFlow).

Funciones principales (nombres alineados con las pruebas R5-01..R5-06 del Lab 7):

- parse_ids_alert      -> r5.alerts      (R5-01)
- classify_alert       -> r5.decision    (R5-02)
- is_malicious_ip      -> r5.intel       (R5-03)
- is_malicious_domain  -> r5.intel       (R5-04)
- build_perimeter_rule -> r5.rules       (R5-05)
- update_blacklist     -> r5.intel       (R5-06)
- log_incident         -> r5.incidents
"""

from .alerts import parse_ids_alert
from .decision import RepeatTracker, classify_alert
from .incidents import log_incident
from .intel import FeedRejected, ThreatIntel
from .model import Action, Alert, Decision
from .policy import Policy, PolicyError, load_policy
from .rules import RuleRejected, build_perimeter_rule

__all__ = [
    "Action", "Alert", "Decision", "FeedRejected", "Policy", "PolicyError",
    "RepeatTracker", "RuleRejected", "ThreatIntel", "build_perimeter_rule",
    "classify_alert", "load_policy", "log_incident", "parse_ids_alert",
]
