#!/usr/bin/env python3
"""Step 5 integrado con el paquete compartido access/ (Lab 7 - Grupo 2).

Cambios respecto a la version de partida (SHA-256 bb2c6b34...):
- Reemplaza la validacion inline por access.validate_credentials(MySQLUserStore(cur), ...).
- Unifica el bloqueo N=8 fallos / 900 s por cuenta O por terminal mediante
  access.LoginGuard(store=MySQLFailureStore(cur)) con locks SQL deterministas.
- Conserva intactos CSRF, cookie segura sdn_portal, binding de vnrt_avz7_portal,
  policy_sync(), auditoria en auth_events y creacion/revocacion de sesiones.
"""
from datetime import datetime, timedelta, timezone
import secrets

from flask import redirect, render_template, request, session, url_for

from access import (
    GENERIC_ERROR,
    LoginGuard,
    MySQLFailureStore,
    MySQLUserStore,
    validate_credentials,
)
import vnrt_portal_paso4 as previous
from vnrt_r1_paso5 import CLIENTS, DPID, HOSTS, sync_request

app = previous.app
db = previous.db
csrf = previous.csrf
token_hash = previous.token_hash
audit = previous.audit

LOCKOUT_MAX_FAILURES = 8
LOCKOUT_WINDOW_SECONDS = 900


class PolicyUnavailable(Exception):
    pass


def policy_sync():
    try:
        return sync_request()
    except Exception as error:
        raise PolicyUnavailable() from error


def terminal_lock(cursor):
    cursor.execute("SELECT GET_LOCK(%s,5) AS locked", ("sdn-r1-" + request.remote_addr,))
    if cursor.fetchone()["locked"] != 1:
        raise PolicyUnavailable()


def identity():
    token = session.get("sid")
    if not token:
        return None
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT u.id,u.username,u.display_name,r.label AS role_label,r.code AS role_code,
             s.network_state,s.terminal_ip,s.terminal_mac,s.switch_dpid,s.in_port,s.expires_at
             FROM sessions s JOIN users u ON s.user_id=u.id JOIN roles r ON r.id=u.role_id
             WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
             AND s.terminal_ip=%s AND u.active=TRUE AND s.role_id=u.role_id
             AND s.network_state IN ('active','denied')""",
            (token_hash(token), request.remote_addr),
        )
        user = cur.fetchone()
    if not user:
        session.pop("sid", None)
    return user


def login():
    raw_username = request.form.get("username", "")
    password = request.form.get("password", "")
    username = raw_username.strip().lower()
    client = CLIENTS.get(request.remote_addr)
    if not client:
        return (
            render_template(
                "login.html",
                csrf=csrf(),
                error="Inicia sesión desde un terminal registrado de la red de datos.",
            ),
            403,
        )

    now = datetime.now(timezone.utc)
    with db() as conn, conn.cursor() as cur:
        failure_store = MySQLFailureStore(cur)
        guard = LoginGuard(
            max_failures=LOCKOUT_MAX_FAILURES,
            window=timedelta(seconds=LOCKOUT_WINDOW_SECONDS),
            store=failure_store,
        )
        try:
            locks = failure_store.acquire_locks(username, request.remote_addr, timeout=5)
        except RuntimeError as error:
            raise PolicyUnavailable() from error

        try:
            if guard.is_locked(now, username=username or None, terminal_ip=request.remote_addr):
                return (
                    render_template(
                        "login.html",
                        csrf=csrf(),
                        error="Demasiados intentos fallidos. Espera 15 minutos.",
                    ),
                    429,
                )

            auth_result = validate_credentials(MySQLUserStore(cur), raw_username, password)
            if not auth_result.ok:
                guard.register_failed_attempt(username, request.remote_addr, now)
                return render_template("login.html", csrf=csrf(), error=GENERIC_ERROR), 401

            policy_sync()  # Fail before creating a new session when the adapter/controller is not ready.
            sw, port, mac, ip = HOSTS[client]
            sid = secrets.token_urlsafe(32)
            # A terminal has one active network identity, even if two browsers are used.
            cur.execute(
                "UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' "
                "WHERE terminal_ip=%s AND revoked_at IS NULL",
                (ip,),
            )
            cur.execute(
                """INSERT INTO sessions(token_hash,user_id,role_id,created_at,expires_at,terminal_ip,
                 terminal_mac,switch_dpid,in_port,network_state)
                 VALUES(%s,%s,%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 15 MINUTE,%s,%s,%s,%s,'pending')""",
                (token_hash(sid), auth_result.user_id, auth_result.role_id, ip, mac, DPID[sw], port),
            )
            try:
                policy_sync()
            except PolicyUnavailable:
                cur.execute(
                    "UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' "
                    "WHERE token_hash=%s",
                    (token_hash(sid),),
                )
                audit(cur, username, "r1_failed")
                raise
            audit(cur, username, "valid_r1")
        finally:
            failure_store.release_locks(locks)

    session.clear()
    session.permanent = True
    session["sid"] = sid
    session["csrf"] = secrets.token_urlsafe(32)
    return redirect(url_for("panel"), code=303)


def panel():
    user = identity()
    if not user:
        return redirect(url_for("index"))
    policy_sync()
    user = identity()
    if not user:
        return redirect(url_for("index"))
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT x.code,x.label,x.ip_address,x.port,x.privileged,x.deployment_state,p.allowed
             FROM role_permissions p JOIN roles r ON p.role_id=r.id JOIN resources x ON p.resource_id=x.id
             WHERE r.code=%s ORDER BY x.id""",
            (user["role_code"],),
        )
        resources = cur.fetchall()
    return render_template("panel.html", user=user, resources=resources, csrf=csrf())


def logout():
    token = session.get("sid")
    if token:
        with db() as conn, conn.cursor() as cur:
            terminal_lock(cur)
            cur.execute(
                """SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id
                 WHERE s.token_hash=%s AND s.terminal_ip=%s""",
                (token_hash(token), request.remote_addr),
            )
            row = cur.fetchone()
            cur.execute(
                "UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' "
                "WHERE token_hash=%s AND terminal_ip=%s",
                (token_hash(token), request.remote_addr),
            )
            if row:
                audit(cur, row["username"], "logout_r1")
            session.clear()
            policy_sync()
    session.clear()
    return redirect(url_for("index"), code=303)


def health():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()
    policy_sync()
    return {
        "status": "ok",
        "database": "mysql",
        "step": 5,
        "network_permissions_enabled": True,
        "scope": "R1/R2 shared access/ module (N=8/900s account+terminal)",
    }


@app.errorhandler(PolicyUnavailable)
def policy_error(error):
    return (
        render_template(
            "error.html",
            message="El control SDN no está disponible. No se concede un nuevo permiso. Vuelve a intentar cuando se recupere.",
        ),
        503,
    )


previous.identity = identity
app.view_functions.update(login=login, panel=panel, logout=logout, health=health)
