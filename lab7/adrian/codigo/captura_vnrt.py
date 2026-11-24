"""Lee las reglas permanentes de sw2 en las tablas 10, 20 y 30 desde app."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

from coherencia import Rule, compare_rules
from collections import Counter


TABLES = {10, 20, 30}
CONTROL_PATH = Path("/opt/sdn-portal-paso4")
INVENTORY_PATH = Path("/etc/sdn-g2/topology.json")


def as_actions(value):
    if isinstance(value, str):
        value = value.split(",") if value else []
    return [action.strip().lower().replace("=", ":", 1) for action in value]


def expected_rule(row):
    attributes = {"switch", "name", "table", "priority", "active", "actions",
                  "idle_timeout", "hard_timeout", "instruction_goto_table"}
    actions = as_actions(row["actions"])
    if "instruction_goto_table" in row:
        actions.append(f'goto_table:{row["instruction_goto_table"]}')
    return {
        "dpid": row["switch"], "table": row["table"], "priority": row["priority"],
        "match": {field: value for field, value in row.items() if field not in attributes},
        "actions": actions, "idle_timeout": row["idle_timeout"], "hard_timeout": row["hard_timeout"],
    }


def observed_rule(row, dpid, metadata):
    instructions = row["instructions"]
    if instructions == {"none": "drop"}:
        instructions = {}
    unsupported = instructions.keys() - {"instruction_apply_actions", "instruction_goto_table"}
    if unsupported:
        raise ValueError(f"Instrucciones sin normalizar: {sorted(unsupported)}")
    actions = as_actions(instructions.get("instruction_apply_actions", {}).get("actions", ""))
    if "instruction_goto_table" in instructions:
        actions.append(f'goto_table:{instructions["instruction_goto_table"]["instruction_goto_table"]}')
    match = dict(row["match"])
    if "metadata" in match:
        bits, mask = metadata(match["metadata"])
        match["metadata"] = f"{bits:#x}/{mask:#x}"
    return {
        "dpid": dpid, "table": row["tableId"], "priority": row["priority"], "match": match,
        "actions": actions, "idle_timeout": row["idleTimeoutSec"], "hard_timeout": row["hardTimeoutSec"],
    }


def capture():
    sys.path.insert(0, str(CONTROL_PATH))
    import vnrt_mt_red as red

    def reference():
        files = (INVENTORY_PATH, Path(red.__file__))
        return {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in files}

    def snapshot():
        rows = red.all_actual()[dpid]
        return [
            observed_rule(row, dpid, red.metadata)
            for row in rows
            if red.number(row["tableId"]) in TABLES and red.number(row["hardTimeoutSec"]) == 0
        ]

    started = datetime.now(timezone.utc).isoformat()
    dpid = red.DPID["sw2"]
    version = reference()
    expected = [
        expected_rule(row)
        for row in red.baseline()
        if row["switch"] == dpid and int(row["table"]) in TABLES and int(row["hard_timeout"]) == 0
    ]
    if not expected:
        raise ValueError("El generador activo no produjo una línea base para sw2")
    first = snapshot()
    second = snapshot()
    stable = Counter(map(Rule.from_record, first)) == Counter(map(Rule.from_record, second))
    result = (
        compare_rules(expected, second)
        if stable and reference() == version
        else {"status": "transitorio", "reason": "Cambió la referencia o la captura permanente"}
    )
    return {
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "source": "Floodlight: estadísticas de reglas efectivas de sw2",
        "scope": {"switch": "sw2", "tables": sorted(TABLES), "hard_timeout": 0},
        "version_sha256": version, "expected": expected, "observed_first": first,
        "observed_second": second, **result,
    }


def main():
    try:
        result = capture()
    except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        result = {"status": "no_verificable", "reason": str(error)}
    print(json.dumps(result, default=str, indent=2))
    return {"coherente": 0, "inconsistente": 1}.get(result["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
