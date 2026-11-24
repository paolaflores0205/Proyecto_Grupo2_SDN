"""Compara capturas normalizadas de reglas OpenFlow en modo observación."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re


IPV4_FIELDS = {"ipv4_src", "ipv4_dst"}
MAC_FIELDS = {"eth_src", "eth_dst"}
INTEGER_FIELDS = {
    "in_port", "eth_type", "ip_proto", "tcp_src", "tcp_dst", "udp_src",
    "udp_dst", "vlan_vid", "icmpv4_type", "icmpv4_code",
}
METADATA_MASK = (1 << 64) - 1


def _integer(value):
    if isinstance(value, str):
        while value.lower().startswith("0x0x"):
            value = value[2:]
        value = int(value, 16 if value.lower().startswith("0x") else 10)
    if type(value) is not int or value < 0:
        raise ValueError(f"Valor entero inválido: {value!r}")
    return value


def _match_value(field, value):
    if field in IPV4_FIELDS:
        return ipaddress.IPv4Network(value, strict=False)
    if field in MAC_FIELDS:
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value, re.I):
            raise ValueError(f"Dirección MAC inválida: {value!r}")
        return value.lower()
    if field in INTEGER_FIELDS:
        return _integer(value)
    if field == "metadata":
        bits, separator, mask = str(value).partition("/")
        bits = _integer(bits)
        mask = _integer(mask) if separator else METADATA_MASK
        if bits > METADATA_MASK or mask > METADATA_MASK:
            raise ValueError("La metadata y su máscara deben caber en 64 bits")
        return bits & mask, mask
    raise ValueError(f"Campo de coincidencia sin normalizar: {field!r}")


@dataclass(frozen=True)
class Rule:
    dpid: int
    table: int
    priority: int
    match: tuple
    actions: tuple[str, ...]
    idle_timeout: int
    hard_timeout: int

    @classmethod
    def from_record(cls, record):
        dpid = record["dpid"]
        if isinstance(dpid, str) and ":" in dpid:
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){7}[0-9a-f]{2}", dpid, re.I):
                raise ValueError(f"DPID inválido: {dpid!r}")
            dpid = "0x" + dpid.replace(":", "")
        match = record["match"]
        actions = record["actions"]
        if not isinstance(match, dict) or not isinstance(actions, list):
            raise ValueError("Se esperan un objeto match y una lista actions")
        if not all(isinstance(action, str) and action.strip() for action in actions):
            raise ValueError("Las acciones deben ser cadenas no vacías")
        actions = tuple(action.strip() for action in actions)
        if len(actions) == 1 and actions[0].lower() == "drop":
            actions = ()
        if any(action.lower() == "drop" for action in actions):
            raise ValueError("DROP debe ser la única acción de la regla")
        normalized_match = {field: _match_value(field, value) for field, value in match.items()}
        if normalized_match.get("metadata") == (0, 0):
            del normalized_match["metadata"]
        return cls(
            dpid=_integer(dpid),
            table=_integer(record["table"]),
            priority=_integer(record["priority"]),
            match=tuple(sorted(normalized_match.items())),
            actions=actions,
            idle_timeout=_integer(record["idle_timeout"]),
            hard_timeout=_integer(record["hard_timeout"]),
        )


def _matches_overlap(first, second):
    first_match = dict(first.match)
    second_match = dict(second.match)
    for field in first_match.keys() & second_match.keys():
        left, right = first_match[field], second_match[field]
        if field in IPV4_FIELDS:
            if not left.overlaps(right):
                return False
        elif field == "metadata":
            left_value, left_mask = left
            right_value, right_mask = right
            if (left_value ^ right_value) & (left_mask & right_mask):
                return False
        elif left != right:
            return False
    return True


def _state(record):
    generations = record["generations"]
    if not isinstance(generations, list):
        raise ValueError("Se espera una lista de generaciones activas")
    return _integer(record["revision"]), frozenset(map(_integer, generations))


def _rules(records):
    if not isinstance(records, list):
        raise ValueError("Se espera una lista de reglas")
    return [Rule.from_record(record) for record in records]


def compare_snapshot(expected, observed):
    """Compara reglas del mismo ámbito, incluidas las variantes que renovaron."""
    if observed["complete"] is not True:
        return {"status": "no_verificable", "reason": "Captura incompleta"}
    before = _state(observed["before"])
    after = _state(observed["after"])
    if before != after:
        return {"status": "transitorio", "reason": "Cambió la revisión o generación durante la captura"}
    if before != _state(expected):
        return {"status": "no_verificable", "reason": "La referencia no corresponde al estado observado"}

    return compare_rules(expected["rules"], observed["rules"], expected.get("drop_checks", []))


def compare_rules(expected, observed, drop_checks=()):
    """Compara reglas ya acotadas y, si se indica, comprueba DROP selectivos."""
    wanted = _rules(expected)
    actual = _rules(observed)
    expected_counts, actual_counts = Counter(wanted), Counter(actual)
    missing = [asdict(rule) for rule in (expected_counts - actual_counts).elements()]
    unexpected = [asdict(rule) for rule in (actual_counts - expected_counts).elements()]
    conflicts = []
    if not isinstance(drop_checks, (list, tuple)):
        raise ValueError("Se espera una lista de índices en drop_checks")
    for index in drop_checks:
        if type(index) is not int or not 0 <= index < len(wanted):
            raise ValueError("Índice inválido en drop_checks")
        drop = wanted[index]
        if drop.actions:
            raise ValueError("drop_checks debe señalar una regla DROP")
        if drop not in actual_counts:
            continue
        for rule in actual_counts:
            if (rule.dpid == drop.dpid and rule.table == drop.table and rule.actions
                    and rule.priority >= drop.priority and _matches_overlap(drop, rule)):
                conflicts.append({"drop": asdict(drop), "competing_rule": asdict(rule)})

    return {
        "status": "inconsistente" if missing or unexpected or conflicts else "coherente",
        "missing": missing,
        "unexpected": unexpected,
        "drop_conflicts": conflicts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("observed", type=Path)
    args = parser.parse_args()
    try:
        expected = json.loads(args.expected.read_text(encoding="utf-8-sig"))
        observed = json.loads(args.observed.read_text(encoding="utf-8-sig"))
        result = compare_snapshot(expected, observed)
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        result = {"status": "no_verificable", "reason": str(error)}
    # Las redes IPv4 se muestran con su prefijo canónico en la evidencia.
    print(json.dumps(result, default=str, ensure_ascii=True, indent=2))
    return {"coherente": 0, "inconsistente": 1}.get(result["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
