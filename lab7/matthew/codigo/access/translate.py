"""R2-03: traduccion de politicas al pipeline multitabla real (sw2 tablas 0/10/20/30 + transito).

Alineado con vnrt_mt_red.py y vnrt_mt_adapter.py:
- sw2 tabla 0: base (default-sw2 -> goto_table=10). Nunca se abren atajos en tabla 0.
- sw2 tabla 10: clasificador de sesion (priority=500+generation, write_metadata, goto_table=20).
- sw2 tabla 20: autorizacion por recurso:
    * lms-shared-sw2-{0,1}: priority=400 (metadata con bit LMS -> goto_table=30)
    * PERMIT exacto (notas/administracion): priority=500+generation (metadata + 5-tupla -> goto_table=30)
    * DENY explicito: priority=550 (metadata + 5-tupla, actions='', sin goto_table -> DROP)
  Al tener priority=550 > 501 > 400, un DENY explicito prevalece siempre sobre PERMIT y sobre
  la regla compartida de LMS, evitando ademas instalar reglas de transito para recursos denegados.
- sw2 tabla 30: enrutamiento de sesion (priority=500+generation, metadata -> output=UP/puerto).
- sw1 (o sw4 en failover) y sw3 tabla 0: transito ida y retorno para recursos permitidos != lms.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .authz import Decision, Resource, normalize_role

PREFIX = "g2-mt-"
LMS_BIT = 1 << 62
ROLE_BITS: Dict[str, int] = {
    "estudiante": 1,
    "docente": 2,
    "administrativo": 3,
    "visitante": 4,
}

LMS_SHARED_PRIORITY = 400
PERMIT_PRIORITY_BASE = 500  # 500 + generation (500 o 501) en vnrt_mt_adapter.py
DENY_PRIORITY = 550         # Estrictamente superior a 500/501 y 400 en sw2 tabla 20

# Topologia D real (/etc/sdn-g2/topology.json)
DPIDS: Dict[str, str] = {
    "sw1": "00:00:00:00:00:00:00:01",
    "sw2": "00:00:00:00:00:00:00:02",
    "sw3": "00:00:00:00:00:00:00:03",
    "sw4": "00:00:00:00:00:00:00:04",
    "sw5": "00:00:00:00:00:00:00:05",
}
SERVER_PORTS: Dict[str, Tuple[str, int, str]] = {
    # ip -> (nombre_host, puerto_sw3, mac) segun /etc/sdn-g2/topology.json
    "192.168.10.101": ("h5", 4, "fa:16:3e:ce:27:f8"),
    "192.168.10.102": ("h4", 3, "fa:16:3e:e3:32:d5"),
}
DEFAULT_SW2_UPLINK = 1
DEFAULT_CORE_PORTS = {"sw1": (1, 2), "sw4": (1, 2)}  # (hacia sw2, hacia sw3) segun topology.json
DEFAULT_SW3_UPLINK = 1


@dataclass(frozen=True)
class Client:
    ip: str
    mac: str
    switch_dpid: str
    in_port: int
    name: str = "h2"


@dataclass(frozen=True)
class PolicyEntry:
    role: str
    resource: Resource
    decision: Decision


def session_context(session_id: str, role: str, lms_allowed: bool) -> int:
    """Calcula metadata local de sw2 identica a vnrt_mt_red.context()."""
    norm = normalize_role(role)
    if norm not in ROLE_BITS:
        raise ValueError(f"Rol sin codigo de metadata en sw2: {role!r}")
    tag = int(hashlib.sha256(session_id.encode()).hexdigest()[:12], 16) & ((1 << 47) - 1)
    return (LMS_BIT if lms_allowed else 0) | (ROLE_BITS[norm] << 48) | (tag << 1)


def _base_flow(sw_dpid: str, name: str, table: int, priority: int, seconds: int, actions: str = "", **fields) -> dict:
    flow = {
        "switch": sw_dpid,
        "name": name,
        "table": str(table),
        "priority": str(priority),
        "active": "true",
        "idle_timeout": "0",
        "hard_timeout": str(seconds),
        "actions": actions,
    }
    for k, v in fields.items():
        flow[k] = str(v)
    return flow


def _resolve_resource_policies(policies: Iterable[PolicyEntry]) -> Tuple[Optional[str], Dict[str, Tuple[Resource, Decision]]]:
    """Consolida politicas por recurso: si coexisten PERMIT y DENY, gana DENY."""
    role: Optional[str] = None
    resolved: Dict[str, Tuple[Resource, Decision]] = {}
    for entry in policies:
        if not isinstance(entry.decision, Decision):
            raise ValueError(f"Decision invalida: {entry.decision!r}")
        if role is None:
            role = normalize_role(entry.role)
        code = entry.resource.code.strip().lower()
        prev = resolved.get(code)
        if prev is None:
            resolved[code] = (entry.resource, entry.decision)
        else:
            # Precedencia: DENY siempre gana sobre PERMIT
            if entry.decision is Decision.DENY or prev[1] is Decision.DENY:
                resolved[code] = (entry.resource, Decision.DENY)
    return role, resolved


def translate_policy(
    policies: Iterable[PolicyEntry],
    client: Client,
    session_id: str = "sess0000000000000001",
    seconds: int = 30,
    generation: int = 1,
    core_switch: str = "sw1",
    sw2_uplink: int = DEFAULT_SW2_UPLINK,
    include_session_rules: bool = True,
    emit_overlapped_permit: bool = False,
    default_role: Optional[str] = None,
) -> List[dict]:
    """Traduce politicas a reglas OpenFlow del pipeline multitabla real (sw2 10/20/30 + transito).

    Parametros clave:
    - generation: 0 o 1 (prioridad 500 o 501 para renovacion sin corte, igual que vnrt_mt_adapter).
    - emit_overlapped_permit: cuando es True (para pruebas de precedencia R2-03), si llegan
      explicitamente PERMIT y DENY sobre el mismo recurso, emite ambos en tabla 20 (PERMIT prio
      500+gen y DENY prio 550) para demostrar que en OVS prevalece el DROP de prioridad 550.
      En operacion normal (False), ni siquiera instala transito para recursos denegados.
    """
    policy_list = list(policies)
    if not policy_list and not default_role:
        return []

    raw_by_code: Dict[str, List[PolicyEntry]] = {}
    for p in policy_list:
        if not isinstance(p.decision, Decision):
            raise ValueError(f"Decision invalida: {p.decision!r}")
        raw_by_code.setdefault(p.resource.code.strip().lower(), []).append(p)

    role, resolved = _resolve_resource_policies(policy_list)
    if role is None and default_role is not None:
        role = normalize_role(default_role)
    if role not in ROLE_BITS:
        raise ValueError(f"Rol no valido para traduccion de plano de datos: {role!r}")
    if core_switch not in ("sw1", "sw4"):
        raise ValueError(f"Switch de nucleo invalido: {core_switch!r}")

    # El bit LMS solo se enciende si LMS tiene decision efectiva PERMIT (nunca si tiene DENY).
    lms_allowed = "lms" in resolved and resolved["lms"][1] is Decision.PERMIT
    ctx = session_context(session_id, role, lms_allowed)
    prio = PERMIT_PRIORITY_BASE + int(generation)
    sid_short = session_id[:16]
    suffix = f"-renew-{generation}"
    flows: List[dict] = []
    seen = set()

    def add(rule: dict) -> None:
        if rule["name"] not in seen:
            seen.add(rule["name"])
            flows.append(rule)

    # 1. Reglas de sesion en sw2 (tablas 10 y 30)
    if include_session_rules:
        for direction in (0, 1):
            fields = {
                "in_port": client.in_port if direction == 0 else sw2_uplink,
                "eth_type": "0x0800",
            }
            fields.update(
                {"eth_src": client.mac, "ipv4_src": f"{client.ip}/32"}
                if direction == 0
                else {"eth_dst": client.mac, "ipv4_dst": f"{client.ip}/32"}
            )
            cls_rule = _base_flow(
                client.switch_dpid,
                f"{PREFIX}session-{sid_short}-{client.name}-class-{direction}{suffix}",
                table=10,
                priority=prio,
                seconds=seconds,
                **fields,
            )
            cls_rule["instruction_write_metadata"] = hex(ctx | direction)
            cls_rule["instruction_goto_table"] = "20"
            add(cls_rule)

            route_rule = _base_flow(
                client.switch_dpid,
                f"{PREFIX}session-{sid_short}-{client.name}-route-{direction}{suffix}",
                table=30,
                priority=prio,
                seconds=seconds,
                actions=f"output={sw2_uplink if direction == 0 else client.in_port}",
                metadata=hex(ctx | direction),
            )
            add(route_rule)

    # 2. Reglas de autorizacion en sw2 tabla 20 y transito en sw1/sw4 + sw3
    for code, (res, eff_decision) in resolved.items():
        if res.plane == "management":
            # Nunca se generan reglas de plano de datos hacia la consola DTI de gestion.
            continue
        proto = "6" if res.transport.lower() == "tcp" else "17"
        port_key_ida = "tcp_dst" if proto == "6" else "udp_dst"
        port_key_ret = "tcp_src" if proto == "6" else "udp_src"
        srv_info = SERVER_PORTS.get(res.ip)
        srv_mac = srv_info[2] if srv_info else "fa:16:3e:00:00:00"
        srv_port_sw3 = srv_info[1] if srv_info else 3

        decisions_to_emit: List[Decision] = []
        raw_decisions = {e.decision for e in raw_by_code[code]}
        if emit_overlapped_permit and raw_decisions == {Decision.PERMIT, Decision.DENY}:
            decisions_to_emit = [Decision.PERMIT, Decision.DENY]
        else:
            decisions_to_emit = [eff_decision]

        for dec in decisions_to_emit:
            if dec is Decision.DENY:
                for direction, label in ((0, "ida"), (1, "retorno")):
                    match_fields = {
                        "in_port": client.in_port if direction == 0 else sw2_uplink,
                        "eth_type": "0x0800",
                        "ip_proto": proto,
                        "metadata": hex(ctx | direction),
                    }
                    if direction == 0:
                        match_fields.update(
                            eth_src=client.mac,
                            eth_dst=srv_mac,
                            ipv4_src=f"{client.ip}/32",
                            ipv4_dst=f"{res.ip}/32",
                            **{port_key_ida: str(res.port)},
                        )
                    else:
                        match_fields.update(
                            eth_src=srv_mac,
                            eth_dst=client.mac,
                            ipv4_src=f"{res.ip}/32",
                            ipv4_dst=f"{client.ip}/32",
                            **{port_key_ret: str(res.port)},
                        )
                    deny_rule = _base_flow(
                        client.switch_dpid,
                        f"{PREFIX}deny-{sid_short}-{client.name}-{code}-{label}-sw2{suffix}",
                        table=20,
                        priority=DENY_PRIORITY,
                        seconds=seconds,
                        actions="",
                        **match_fields,
                    )
                    add(deny_rule)
            else:
                # PERMIT
                if code == "lms" and not emit_overlapped_permit:
                    # LMS permitido se atiende via metadata LMS_BIT + lms-shared-sw2 (prio 400).
                    continue
                for direction, label in ((0, "ida"), (1, "retorno")):
                    match_sw2 = {
                        "in_port": client.in_port if direction == 0 else sw2_uplink,
                        "eth_type": "0x0800",
                        "ip_proto": proto,
                        "metadata": hex(ctx | direction),
                    }
                    if direction == 0:
                        match_sw2.update(
                            eth_src=client.mac,
                            eth_dst=srv_mac,
                            ipv4_src=f"{client.ip}/32",
                            ipv4_dst=f"{res.ip}/32",
                            **{port_key_ida: str(res.port)},
                        )
                    else:
                        match_sw2.update(
                            eth_src=srv_mac,
                            eth_dst=client.mac,
                            ipv4_src=f"{res.ip}/32",
                            ipv4_dst=f"{client.ip}/32",
                            **{port_key_ret: str(res.port)},
                        )
                    permit_sw2 = _base_flow(
                        client.switch_dpid,
                        f"{PREFIX}grant-{sid_short}-{client.name}-{code}-{label}-sw2{suffix}",
                        table=20,
                        priority=prio,
                        seconds=seconds,
                        actions="",
                        **match_sw2,
                    )
                    permit_sw2["instruction_goto_table"] = "30"
                    add(permit_sw2)

                # Transito en nucleo (sw1 o sw4) y sw3 solo si decision efectiva es PERMIT y != lms
                if eff_decision is Decision.PERMIT and code != "lms":
                    c_in, c_out = DEFAULT_CORE_PORTS[core_switch]
                    for direction, label in ((0, "ida"), (1, "retorno")):
                        common = {"eth_type": "0x0800", "ip_proto": proto}
                        if direction == 0:
                            common.update(
                                eth_src=client.mac,
                                eth_dst=srv_mac,
                                ipv4_src=f"{client.ip}/32",
                                ipv4_dst=f"{res.ip}/32",
                                **{port_key_ida: str(res.port)},
                            )
                        else:
                            common.update(
                                eth_src=srv_mac,
                                eth_dst=client.mac,
                                ipv4_src=f"{res.ip}/32",
                                ipv4_dst=f"{client.ip}/32",
                                **{port_key_ret: str(res.port)},
                            )
                        add(
                            _base_flow(
                                DPIDS[core_switch],
                                f"{PREFIX}grant-{sid_short}-{client.name}-{code}-{label}-{core_switch}{suffix}",
                                table=0,
                                priority=prio,
                                seconds=seconds,
                                actions=f"output={c_out if direction == 0 else c_in}",
                                in_port=c_in if direction == 0 else c_out,
                                **common,
                            )
                        )
                        add(
                            _base_flow(
                                DPIDS["sw3"],
                                f"{PREFIX}grant-{sid_short}-{client.name}-{code}-{label}-sw3{suffix}",
                                table=0,
                                priority=prio,
                                seconds=seconds,
                                actions=f"output={srv_port_sw3 if direction == 0 else DEFAULT_SW3_UPLINK}",
                                in_port=DEFAULT_SW3_UPLINK if direction == 0 else srv_port_sw3,
                                **common,
                            )
                        )
    return flows


_MATCH_KEYS = (
    "switch",
    "table",
    "in_port",
    "eth_src",
    "eth_dst",
    "eth_type",
    "ip_proto",
    "ipv4_src",
    "ipv4_dst",
    "tcp_src",
    "tcp_dst",
    "udp_src",
    "udp_dst",
    "metadata",
)


def effective_actions(flows: Iterable[dict]) -> Dict[Tuple, str]:
    """Para cada match identico en (switch, tabla, campos), devuelve la accion ganadora.

    Si la regla ganadora tiene instruction_goto_table, devuelve 'goto_table:<N>';
    si tiene actions='', devuelve '' (DROP).
    """
    best: Dict[Tuple, Tuple[int, str]] = {}
    for f in flows:
        key = tuple(f.get(k) for k in _MATCH_KEYS)
        prio = int(f["priority"])
        eff = f.get("actions", "")
        if not eff and "instruction_goto_table" in f:
            eff = f"goto_table:{f['instruction_goto_table']}"
        if key not in best or prio > best[key][0]:
            best[key] = (prio, eff)
    return {k: v[1] for k, v in best.items()}


def effective_table20_decision(flows: Iterable[dict]) -> Dict[Tuple, Decision]:
    """Evalua la decision efectiva en tabla 20 de sw2: goto_table:30 -> PERMIT, '' -> DENY."""
    t20 = [f for f in flows if f.get("switch") == DPIDS["sw2"] and str(f.get("table")) == "20"]
    resolved = effective_actions(t20)
    return {
        k: (Decision.PERMIT if act == "goto_table:30" else Decision.DENY)
        for k, act in resolved.items()
    }
