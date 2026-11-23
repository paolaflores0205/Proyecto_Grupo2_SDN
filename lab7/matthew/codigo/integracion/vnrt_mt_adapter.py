"""Adaptador multitabla integrado con el paquete compartido access/ (Lab 7 - Grupo 2).

Cambios respecto a la version de partida (SHA-256 ed3d92c7...):
- Evalua permisos con access.load_access_matrix_from_rows() y access.evaluate_access()
  conservando DENY por defecto y precedencia de denegacion explicita.
- Traduce las politicas al pipeline multitabla real (sw2 tablas 0/10/20/30 + transito sw1/sw4/sw3)
  usando access.translate_policy() / vnrt_mt_red.py con prioridad DENY=550 > PERMIT=500/501 > LMS=400.
- Conserva intactos policy_revision, AuthorizationChanged, reconciliacion con GET_LOCK,
  renovacion sin corte por generaciones 500/501, retiro selectivo y fail_closed().
"""
from datetime import datetime, timezone
import hashlib
import json
import time

from access import (
    DENY_PRIORITY,
    Client,
    Decision,
    PolicyEntry,
    evaluate_access,
    load_access_matrix_from_rows,
    translate_policy,
)
import vnrt_avz7_adapter as old
import vnrt_mt_red as red
import vnrt_r1_paso5 as previous

db = previous.db
binding = old.binding
EDGE_DPIDS = frozenset(red.DPID[name] for name in ("sw2", "sw3", "sw5"))
PRIMARY_DPIDS = frozenset(red.DPID[name] for name in ("sw1", "sw2", "sw3", "sw5"))
CORE_PRIORITY = (red.DPID["sw1"], red.DPID["sw4"])
DPID_TO_CORE = {red.DPID["sw1"]: "sw1", red.DPID["sw4"]: "sw4"}


def active_tree_state():
    connected = {row["switchDPID"] for row in red.api("/wm/core/controller/switches/json")}
    missing_edges = EDGE_DPIDS - connected
    if missing_edges:
        raise RuntimeError("Edge switch unavailable: " + ", ".join(sorted(missing_edges)))
    for core in CORE_PRIORITY:
        if core in connected:
            return core, EDGE_DPIDS | {core}, connected
    raise RuntimeError("No core switch available (sw1/sw4 offline)")


def require_primary_switches():
    _, _, connected = active_tree_state()
    return connected


def primary_actual():
    _, tree, connected = active_tree_state()
    observed = red.api("/wm/core/switch/all/flow/json")
    if not isinstance(observed, dict):
        raise RuntimeError("Invalid active-tree flow snapshot")
    result = {}
    for dpid in sorted(tree):
        entry = observed.get(dpid)
        flows = entry.get("flows") if isinstance(entry, dict) else None
        if not isinstance(flows, list) or any(
            not isinstance(rule, dict) or not {"priority", "match"} <= rule.keys() for rule in flows
        ):
            raise RuntimeError("Incomplete active-tree flow snapshot: " + dpid)
        result[dpid] = flows
    for dpid in sorted((set(red.DPID.values()) & connected) - tree):
        entry = observed.get(dpid)
        flows = entry.get("flows") if isinstance(entry, dict) else None
        if isinstance(flows, list):
            result[dpid] = flows
    return result


red.all_actual = primary_actual


class AuthorizationChanged(RuntimeError):
    """La autorizacion cambio; reintentar con una instantanea nueva."""


def snapshot(cur):
    cur.execute("SELECT revision FROM policy_revision WHERE id=1")
    revision = cur.fetchone()["revision"]
    cur.execute(
        """SELECT s.token_hash,s.user_id,s.role_id,s.created_at,s.expires_at,s.terminal_ip,s.terminal_mac,
        s.switch_dpid,s.in_port,u.active,u.role_id AS current_role,r.code AS role_code
        FROM sessions s JOIN users u ON u.id=s.user_id JOIN roles r ON r.id=u.role_id
        WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
        ORDER BY s.created_at DESC"""
    )
    sessions = cur.fetchall()
    cur.execute(
        """SELECT p.role_id,r.code AS role_code,p.allowed,x.code,x.ip_address,x.port,x.transport,x.privileged,x.deployment_state
        FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id
        ORDER BY p.role_id,x.code"""
    )
    policies = cur.fetchall()
    digest = hashlib.sha256(json.dumps([sessions, policies], sort_keys=True, default=str).encode()).hexdigest()
    cur.execute("SELECT revision FROM policy_revision WHERE id=1")
    if cur.fetchone()["revision"] != revision:
        raise AuthorizationChanged("Authorization changed during snapshot")
    return revision, digest, sessions, policies


def build_client_plan(row, matrix, client_name, seconds, generation, active_core_name, explicit_denies=()):
    """Evalua la matriz real con evaluate_access() y traduce con translate_policy()."""
    role = row["role_code"]
    sid = row["token_hash"]
    states = {}
    entries = []
    for code in red.SPEC:
        decision = evaluate_access(matrix, role, code)
        states[code] = "active" if decision.decision is Decision.PERMIT else "denied"
        res = matrix.resources.get(code)
        if res is not None:
            if decision.decision is Decision.PERMIT:
                entries.append(PolicyEntry(role, res, Decision.PERMIT))
            elif (role, code) in explicit_denies or code in explicit_denies:
                entries.append(PolicyEntry(role, res, Decision.DENY))

    client = Client(
        ip=row["terminal_ip"],
        mac=row["terminal_mac"],
        switch_dpid=row["switch_dpid"],
        in_port=int(row["in_port"]),
        name=client_name,
    )
    # Si no hubo entradas PERMIT (ej. visitante), translate_policy emite solo session_rules con lms=False
    # para que el trafico caiga en miss-20 (default DROP de tabla 20).
    flows = translate_policy(
        entries,
        client,
        session_id=sid,
        seconds=seconds,
        generation=generation,
        core_switch=active_core_name,
        sw2_uplink=red.UP,
        include_session_rules=True,
        default_role=role,
    )
    return states, flows


class Reconciler:
    def __init__(self):
        self.current = {}

    def sync(self):
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT GET_LOCK('sdn-mt-worker',2) AS locked")
            if cur.fetchone()["locked"] != 1:
                raise RuntimeError("Another worker owns enforcement")
            try:
                for attempt in range(3):
                    try:
                        return self.enforce(cur)
                    except AuthorizationChanged:
                        if attempt == 2:
                            raise
            finally:
                cur.execute("SELECT RELEASE_LOCK('sdn-mt-worker')")

    def enforce(self, cur):
        active_core, active_tree, connected = active_tree_state()
        active_core_name = DPID_TO_CORE[active_core]
        required_baseline = [rule for rule in red.baseline() if rule["switch"] in active_tree]
        if not {rule["name"] for rule in required_baseline}.issubset(red.stored_names()):
            if set(red.DPID.values()) != connected:
                raise RuntimeError("Active baseline missing while topology is degraded")
            red.all_actual = old.batched_actual
            try:
                red.bootstrap()
            finally:
                red.all_actual = primary_actual

        revision, digest, rows, policy_rows = snapshot(cur)
        matrix = load_access_matrix_from_rows(policy_rows)
        devices = red.api("/wm/device/")
        wanted = []
        decisions = {}
        tokens = {}
        links = {}
        plans = {}
        contexts = set()

        for row in rows:
            client = red.CLIENTS.get(row["terminal_ip"])
            if not client or client in decisions or not row["active"] or row["role_id"] != row["current_role"]:
                continue
            try:
                b = binding(client, devices)
            except RuntimeError:
                continue
            if (row["terminal_mac"], row["switch_dpid"], row["in_port"]) != (b["mac"], b["dpid"], b["port"]):
                continue
            seconds = min(
                30, int((row["expires_at"] - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()) - 2
            )
            if seconds <= 0:
                continue

            sid = row["token_hash"]
            role = row["role_code"]
            states = {}
            for code in red.SPEC:
                dec = evaluate_access(matrix, role, code)
                states[code] = "active" if dec.decision is Decision.PERMIT else "denied"
            lms = states["lms"] == "active"
            ctx = red.context(sid, role, lms)
            if ctx in contexts:
                raise RuntimeError("Session metadata collision")
            contexts.add(ctx)

            prior = self.current.get(client)
            signature = (sid, role, tuple(states.items()))
            present_now = red.stored_names()
            prior_gen = prior[2] if prior else 1
            _, check_group = build_client_plan(row, matrix, client, seconds, prior_gen, active_core_name)
            due = (
                not prior
                or prior[0] != signature
                or time.monotonic() - prior[1] >= 10
                or not {f["name"] for f in check_group}.issubset(present_now)
            )
            generation = (1 - prior[2]) if (due and prior) else (prior[2] if prior else 1)
            _, group = build_client_plan(row, matrix, client, seconds, generation, active_core_name)
            for f in group:
                if "-session-" in f["name"]:
                    links[f["name"]] = (sid, "session")
                else:
                    matched_code = next((c for c in red.SPEC if f"-{c}-" in f["name"]), "policy")
                    links[f["name"]] = (sid, matched_code)
            plans[client] = (signature, group, generation, due)
            tokens[client] = sid
            decisions[client] = states

        def guard():
            fresh = snapshot(cur)
            if fresh[0] != revision or fresh[1] != digest:
                raise AuthorizationChanged("Stale authorization revision rejected")

        invalid = [r["token_hash"] for r in rows if r["token_hash"] not in set(tokens.values())]
        if invalid:
            guard()
            cur.execute(
                "UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked',session_state='REVOKED',enforcement_state='PENDING' "
                "WHERE revoked_at IS NULL AND token_hash IN (" + ",".join(["%s"] * len(invalid)) + ")",
                tuple(invalid),
            )
            raise RuntimeError("Invalid binding/account/session retired; re-evaluation required")

        guard()
        present = red.stored_names()
        red.remove(
            [
                n
                for n in present
                if n.startswith((red.P + "session-", red.P + "grant-", red.P + "deny-"))
                and not any("-" + client + "-" in n for client in plans)
            ]
        )

        final_plans = {}
        for client, (signature, group, generation, due) in plans.items():
            prior = self.current.get(client)
            present_group = [
                n
                for n in present
                if n.startswith((red.P + "session-", red.P + "grant-", red.P + "deny-")) and "-" + client + "-" in n
            ]
            if due:
                guard()
                same_authorization = bool(prior and prior[0] == signature)
                if not same_authorization:
                    red.remove(present_group)
                for f in sorted(
                    group,
                    key=lambda f: 0
                    if f["switch"] != red.DPID["sw2"]
                    else 1
                    if f["table"] == "30"
                    else 2
                    if f["table"] == "20"
                    else 3,
                ):
                    guard()
                    red.push(f)
                red.verify_actual(group)
                red.remove([n for n in present_group if n not in {f["name"] for f in group}])
                self.current[client] = (signature, time.monotonic(), generation)
            final_plans[client] = (signature, group)

        wanted = [f for _, group in final_plans.values() for f in group]
        expected = {f["name"] for f in wanted}
        red.remove(
            [
                n
                for n in red.stored_names()
                if n.startswith((red.P + "session-", red.P + "grant-", red.P + "deny-")) and n not in expected
            ]
        )
        until = time.monotonic() + 5
        while True:
            observed = red.verify_actual(wanted)
            actual_count = sum(
                red.number(r["priority"]) in (500, 501, DENY_PRIORITY) for rules in observed.values() for r in rules
            )
            if actual_count == len(wanted):
                break
            if time.monotonic() > until:
                raise RuntimeError("Unexpected session rules")
            time.sleep(0.2)

        guard()
        for client in decisions:
            binding(client)
        guard()
        cur.execute(
            "UPDATE sessions SET session_state='EXPIRED',network_state='revoked',enforcement_state='VERIFIED' "
            "WHERE revoked_at IS NULL AND expires_at<=UTC_TIMESTAMP(6)"
        )
        cur.execute(
            "UPDATE sessions SET session_state='REVOKED',network_state='revoked',enforcement_state='VERIFIED' "
            "WHERE revoked_at IS NOT NULL"
        )
        for client, sid in tokens.items():
            state = "active" if any(v == "active" for v in decisions[client].values()) else "denied"
            cur.execute(
                "UPDATE sessions SET session_state='ACTIVE',network_state=%s,enforcement_state='VERIFIED' "
                "WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)",
                (state, sid),
            )
        cur.execute("UPDATE network_rules SET enforcement_state='RETIRED' WHERE enforcement_state IN ('VERIFIED','PENDING_RETIRE')")
        for f in wanted:
            sid, code = links[f["name"]]
            record = dict(f, authorization_revision=revision)
            cur.execute(
                """INSERT INTO network_rules(rule_name,session_id,resource_code,switch_dpid,rule_json,enforcement_state,updated_at)
                VALUES(%s,%s,%s,%s,%s,'VERIFIED',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE rule_json=VALUES(rule_json),enforcement_state='VERIFIED',updated_at=UTC_TIMESTAMP(6)""",
                (f["name"], sid, code, f["switch"], json.dumps(record)),
            )
        guard()
        self.current = {k: v for k, v in self.current.items() if k in final_plans}
        return {
            "ok": True,
            "terminals": {c: "active" if any(v == "active" for v in s.values()) else "denied" for c, s in decisions.items()},
            "resources": decisions,
            "actual_individual_rules": len(wanted),
            "session_rules": 4 * len(final_plans),
            "r2_rules": len(wanted) - 4 * len(final_plans),
            "baseline_rules": len(red.baseline()),
            "authorization_revision": revision,
            "metadata": True,
        }

    def fail_closed(self):
        self.current.clear()
        try:
            red.remove(
                [n for n in red.stored_names() if n.startswith((red.P + "session-", red.P + "grant-", red.P + "deny-"))]
            )
        except Exception:
            pass
        try:
            with db() as conn, conn.cursor() as cur:
                cur.execute("UPDATE sessions SET enforcement_state='FAILED' WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)")
                cur.execute("UPDATE network_rules SET enforcement_state='PENDING_RETIRE' WHERE enforcement_state='VERIFIED'")
        except Exception:
            pass


def daemon():
    previous.Reconciler = Reconciler
    previous.daemon()


if __name__ == "__main__":
    daemon()
