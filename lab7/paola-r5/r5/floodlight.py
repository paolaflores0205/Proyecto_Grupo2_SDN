"""Backend real: Floodlight Static Flow Pusher por REST.

En la VM app la API de Floodlight se alcanza en http://127.0.0.1:8080 a traves del
tunel `sdn-rest-tunnel` (el mismo que usan sdn-r1 y sdn-r4).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Set


class FloodlightError(RuntimeError):
    """Floodlight no respondio o rechazo la operacion."""


class FloodlightBackend:
    def __init__(self, base_url: str, switch_dpid: str, prefix: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.switch_dpid = switch_dpid
        self.prefix = prefix
        self.timeout = timeout

    def _request(self, path: str, method: str = "GET", body: Optional[dict] = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            raise FloodlightError(f"{method} {path}: {exc}") from exc
        try:
            return json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            raise FloodlightError(f"{method} {path}: respuesta no JSON") from exc

    def list_rules(self, prefix: Optional[str] = None) -> Dict[str, dict]:
        """Reglas del Static Flow Pusher en el switch de borde cuyo nombre empieza con el prefijo."""
        prefix = self.prefix if prefix is None else prefix
        raw = self._request(f"/wm/staticflowpusher/list/{self.switch_dpid}/json")
        entries = raw.get(self.switch_dpid, []) if isinstance(raw, dict) else []
        rules: Dict[str, dict] = {}
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict):
                for name, body in entry.items():
                    if name.startswith(prefix.rstrip("-") + "-"):
                        rules[name] = body
        return rules

    def existing_rule_names(self) -> Set[str]:
        return set(self.list_rules())

    def install(self, rule: dict) -> None:
        reply = self._request("/wm/staticflowpusher/json", "POST", rule)
        if "pushed" not in json.dumps(reply).lower():
            raise FloodlightError(f"Floodlight rechazo {rule.get('name')}: {reply}")

    def remove(self, name: str) -> None:
        if not name.startswith(self.prefix.rstrip("-") + "-"):
            raise FloodlightError("Se rechazo borrar una regla ajena al modulo")
        self._request("/wm/staticflowpusher/json", "DELETE", {"name": name})
        if name in self.existing_rule_names():
            raise FloodlightError(f"Floodlight conserva {name} despues del DELETE")

    def connected_switches(self) -> List[str]:
        raw = self._request("/wm/core/controller/switches/json")
        return sorted(s.get("switchDPID", "") for s in raw) if isinstance(raw, list) else []
