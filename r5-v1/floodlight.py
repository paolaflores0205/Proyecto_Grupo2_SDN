"""Adaptador R5 independiente para la API local del Floodlight inspeccionado.

Construir el objeto no abre conexiones. No se ejecuta nada al importar.
Los métodos de escritura requieren habilitación explícita por el llamador.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import time
from urllib.parse import urlsplit


class IntegrationError(RuntimeError):
    pass


def number(value):
    if isinstance(value, dict):
        value = value.get("value", value.get("portNumber"))
    if isinstance(value, bool):
        raise IntegrationError("Valor numérico inesperado en Floodlight")
    text = str(value).lower()
    while text.startswith("0x0x"):
        text = text[2:]
    return int(text, 16) if text.startswith("0x") else int(text)


def same_value(key, a, b):
    if key.startswith("ipv4_"):
        return ipaddress.ip_network(str(a), strict=False) == ipaddress.ip_network(str(b), strict=False)
    if key.startswith("eth_") and key != "eth_type":
        return str(a).lower() == str(b).lower()
    return number(a) == number(b)


def flow_rows(value):
    rows = []
    if isinstance(value, dict):
        if "match" in value and "priority" in value:
            rows.append(value)
        else:
            for child in value.values():
                rows.extend(flow_rows(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(flow_rows(child))
    return rows


def matches_drop(rule, observed):
    """Comparación estricta del match, instrucciones y vigencia, sin usar nombres OVS."""
    keys = {"in_port", "eth_type", "ip_proto", "ipv4_src", "ipv4_dst", "tcp_dst", "udp_dst"}
    try:
        if number(observed.get("tableId", observed.get("table_id", -1))) != 0:
            return False
        if number(observed["priority"]) != int(rule["priority"]):
            return False
        expected = {k: v for k, v in rule.items() if k in keys}
        match = observed["match"]
        if set(match) != set(expected) or not all(same_value(k, v, match[k]) for k, v in expected.items()):
            return False
        instructions = observed.get("instructions")
        if not isinstance(instructions, dict):
            return False
        if instructions == {"none": "drop"}:
            instructions = {}
        # Cualquier goto, write-actions, metadata o meter queda fuera del drop previsto.
        if set(instructions) - {"instruction_apply_actions"}:
            return False
        actions = instructions.get("instruction_apply_actions", {})
        if not isinstance(actions, dict) or actions.get("actions", "") not in ("", []):
            return False
        return (number(observed.get("hardTimeoutSec", -1)) == int(rule["hard_timeout"])
                and number(observed.get("idleTimeoutSec", -1)) == 0)
    except (KeyError, ValueError, TypeError):
        return False


def overlaps(rule, observed):
    """Conservador: no descarta conflicto si el formato de algún campo es desconocido."""
    try:
        for key, value in observed.get("match", {}).items():
            if key not in rule:
                continue
            if key.startswith("ipv4_"):
                if not ipaddress.ip_network(str(value), strict=False).overlaps(
                        ipaddress.ip_network(str(rule[key]), strict=False)):
                    return False
            elif not same_value(key, value, rule[key]):
                return False
    except (ValueError, TypeError, IntegrationError):
        return True
    return True


class LocalHTTP:
    """HTTP sin proxies/redirecciones; solo loopback y el puerto elegido."""
    def __init__(self, base_url="http://127.0.0.1:8080", timeout=5):
        url = urlsplit(base_url)
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost"}
                or url.username or url.password or url.path not in {"", "/"}
                or url.query or url.fragment):
            raise IntegrationError("Usar la API HTTP local, sin credenciales en URL")
        self.host, self.port, self.timeout = url.hostname, url.port or 8080, timeout

    def __call__(self, path, method="GET", data=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            body = None if data is None else json.dumps(data).encode()
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            payload = response.read(2_000_001)
            if response.status != 200 or len(payload) > 2_000_000:
                raise IntegrationError(f"Respuesta API no válida: HTTP {response.status}")
            return json.loads(payload)
        finally:
            conn.close()


class FloodlightSwitch:
    simulation = False

    def __init__(self, switch_dpid, *, enable_writes=False, request=None,
                 verification_timeout=5, poll_interval=0.2):
        self.dpid = switch_dpid.lower()
        self.enable_writes = enable_writes
        self.request = request if request is not None else LocalHTTP()
        self.verification_timeout = verification_timeout
        self.poll_interval = poll_interval
        self.expected = {}

    def track(self, rule):
        """Registra una regla de la bitácora local; no escribe en el controlador."""
        required = {"switch", "name", "table", "priority", "active", "idle_timeout",
                    "hard_timeout", "in_port", "eth_type", "ip_proto", "ipv4_src",
                    "ipv4_dst", "actions"}
        proto_key = "tcp_dst" if rule.get("ip_proto") == "6" else "udp_dst"
        if (set(rule) != required | {proto_key}
                or rule.get("ip_proto") not in {"6", "17"}
                or rule.get("switch") != self.dpid
                or not re.fullmatch(r"g2-r5-adrian-[0-9a-f]{24}", rule.get("name", ""))
                or rule.get("table") != "0" or rule.get("actions") != ""
                or rule.get("active") != "true" or rule.get("idle_timeout") != "0"
                or rule.get("eth_type") != "0x0800"):
            raise IntegrationError("Solo se admiten las reglas drop propias de R5")
        try:
            if not 1 <= int(rule["hard_timeout"]) <= 300 or not 1 <= int(rule["priority"]) <= 65535:
                raise ValueError()
            if not 1 <= int(rule["in_port"]) <= 65279 or not 1 <= int(rule[proto_key]) <= 65535:
                raise ValueError()
            if any(ipaddress.ip_network(rule[k]).prefixlen != 32 for k in ("ipv4_src", "ipv4_dst")):
                raise ValueError()
        except (ValueError, TypeError):
            raise IntegrationError("Regla fuera de los límites del ensayo") from None
        self.expected[rule["name"]] = dict(rule)

    def _rows(self):
        return flow_rows(self.request(f"/wm/core/switch/{self.dpid}/flow/json"))

    def _stored(self, name):
        data = self.request("/wm/staticflowpusher/list/all/json")
        found = []
        def visit(value, switch=None):
            if isinstance(value, list):
                for item in value:
                    visit(item, switch)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if key == name:
                        found.append((switch, item))
                    elif isinstance(item, (list, dict)):
                        visit(item, key if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}", key) else switch)
        visit(data)
        if len(found) > 1:
            raise IntegrationError("Nombre de regla ambiguo en el pusher")
        return found[0] if found else None

    def _stored_matches(self, stored, rule):
        switch, fields = stored
        if switch != self.dpid or not isinstance(fields, dict):
            return False
        if "match" in fields and "instructions" in fields:
            # El build inspeccionado serializa OFFlowMod, no el JSON enviado.
            observed = dict(fields, tableId=fields.get("tableId", fields.get("table_id", 0)))
            return matches_drop(rule, observed)
        return all(str(fields.get(k)) == str(v) for k, v in rule.items() if k not in {"name", "switch"})

    def preflight(self, rule):
        """Consultas GET; no comprueba disponibilidad del servicio de datos."""
        self.track(rule)
        switches = self.request("/wm/core/controller/switches/json")
        if self.dpid not in {x.get("switchDPID", "").lower() for x in switches}:
            raise IntegrationError("El switch objetivo no está conectado")
        if self._stored(rule["name"]) is not None:
            raise IntegrationError("El nombre ya existe; consultar antes de reintentar")
        rows = self._rows()
        for row in rows:
            if (number(row.get("tableId", row.get("table_id", -1))) == 0
                    and number(row["priority"]) >= int(rule["priority"]) and overlaps(rule, row)):
                raise IntegrationError("Otra regla de prioridad igual o mayor puede coincidir")
        return {"connected": True, "conflicting_rules": 0, "flows_observed": len(rows)}

    def install(self, rule):
        if not self.enable_writes:
            raise IntegrationError("Escrituras deshabilitadas")
        self.preflight(rule)
        reply = self.request("/wm/staticflowpusher/json", "POST", rule)
        if not isinstance(reply, dict) or "pushed" not in str(reply.get("status", "")).lower():
            raise IntegrationError("Instalación sin confirmación válida")

    def observe(self, name):
        rule = self.expected.get(name)
        if rule is None:
            raise IntegrationError("Regla no registrada por este componente")
        deadline = time.monotonic() + self.verification_timeout
        while True:
            candidates = [row for row in self._rows() if matches_drop(rule, row)]
            if len(candidates) == 1:
                # Es regla observada, no evidencia de bloqueo de paquetes.
                return dict(rule)
            if len(candidates) > 1:
                raise IntegrationError("Coincidencia de regla ambigua")
            if time.monotonic() >= deadline:
                return None
            time.sleep(self.poll_interval)

    def remove(self, name):
        if not self.enable_writes:
            raise IntegrationError("Escrituras deshabilitadas")
        rule = self.expected.get(name)
        if rule is None:
            raise IntegrationError("No se pueden retirar reglas no registradas")
        stored = self._stored(name)
        for row in self._rows():
            if (number(row.get("tableId", row.get("table_id", -1))) == 0
                    and number(row["priority"]) == int(rule["priority"])
                    and overlaps(rule, row) and not matches_drop(rule, row)):
                raise IntegrationError("La entrada de dataplane difiere; no se retira")
        if stored is not None:
            switch, fields = stored
            if not self._stored_matches(stored, rule):
                raise IntegrationError("La entrada del pusher cambió; no se retira")
            self.request("/wm/staticflowpusher/json", "DELETE", {"name": name})
        deadline = time.monotonic() + self.verification_timeout
        while True:
            if self._stored(name) is None and not any(matches_drop(rule, row) for row in self._rows()):
                return
            if time.monotonic() >= deadline:
                raise IntegrationError("Retiro sin confirmar en pusher y dataplane")
            time.sleep(self.poll_interval)
