"""Guarda evidencia de lectura en una carpeta nueva; no instala ni retira reglas."""
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from floodlight import LocalHTTP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path, help="snapshot.json anterior opcional")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    get = LocalHTTP()
    result = {"recorded_at": datetime.now(timezone.utc).isoformat(), "source_hashes": {},
              "services": {}, "api": {}}
    for folder in ("/opt/sdn-portal-paso4", "/opt/sdn-admin-paso7", "/opt/sdn-floodlight"):
        for path in sorted(Path(folder).glob("*")):
            if path.is_file() and path.suffix in {".py", ".properties", ".jar"}:
                try:
                    with path.open("rb") as stream:
                        result["source_hashes"][str(path)] = hashlib.file_digest(stream, "sha256").hexdigest()
                except OSError:
                    result["source_hashes"][str(path)] = "UNREADABLE"
    for unit in ("sdn-r1", "sdn-portal", "sdn-admin", "sdn-dhcp", "sdn-floodlight", "mysql"):
        run = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        result["services"][unit] = run.stdout.strip()
    for path in ("/wm/core/controller/switches/json", "/wm/topology/links/json",
                 "/wm/device/", "/wm/staticflowpusher/list/all/json"):
        result["api"][path] = get(path)
    switches = result["api"]["/wm/core/controller/switches/json"]
    for sw in switches:
        path = "/wm/core/switch/" + sw["switchDPID"] + "/flow/json"
        result["api"][path] = get(path)
    (args.output / "snapshot.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary = {"status": "SNAPSHOT_SAVED_READ_ONLY", "directory": str(args.output),
               "files_hashed": len(result["source_hashes"]), "services": result["services"]}
    if args.compare:
        previous = json.loads(args.compare.read_text(encoding="utf-8"))
        old = previous["api"]["/wm/staticflowpusher/list/all/json"]
        current = result["api"]["/wm/staticflowpusher/list/all/json"]
        summary["source_hashes_unchanged"] = previous["source_hashes"] == result["source_hashes"]
        summary["services_unchanged"] = previous["services"] == result["services"]
        summary["pusher_definitions_unchanged"] = old == current
        summary["comparison_note"] = "Los contadores/duraciones pueden variar con la operación normal"
        (args.output / "comparison.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
