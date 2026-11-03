#!/usr/bin/env python3
"""Step 5 extends the preserved step 4 portal; credentials never become flow fields."""
from datetime import datetime, timezone
import re
import secrets
from flask import redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
import vnrt_portal_paso4 as previous
from vnrt_r1_paso5 import CLIENTS, HOSTS, DPID, sync_request
app=previous.app
db=previous.db
csrf=previous.csrf
token_hash=previous.token_hash
audit=previous.audit

class PolicyUnavailable(Exception): pass

def policy_sync():
    try: return sync_request()
    except Exception as error: raise PolicyUnavailable() from error

def terminal_lock(cursor):
    cursor.execute('SELECT GET_LOCK(%s,5) AS locked',('sdn-r1-'+request.remote_addr,))
    if cursor.fetchone()['locked']!=1: raise PolicyUnavailable()

def identity():
    token=session.get('sid')
    if not token: return None
    with db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT u.id,u.username,u.display_name,r.label AS role_label,r.code AS role_code,
         s.network_state,s.terminal_ip,s.terminal_mac,s.switch_dpid,s.in_port,s.expires_at
         FROM sessions s JOIN users u ON s.user_id=u.id JOIN roles r ON r.id=u.role_id
         WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
         AND s.terminal_ip=%s AND u.active=TRUE AND s.role_id=u.role_id
         AND s.network_state IN ('active','denied')''',(token_hash(token),request.remote_addr))
        user=cur.fetchone()
    if not user: session.pop('sid',None)
    return user

def login():
    username=request.form.get('username','').strip().lower(); password=request.form.get('password','')
    if not re.fullmatch(r'[a-z0-9_]{1,64}',username) or not 1<=len(password)<=256:
        return render_template('login.html',csrf=csrf(),error='Usuario o contraseña inválidos.'),401
    client=CLIENTS.get(request.remote_addr)
    if not client:
        return render_template('login.html',csrf=csrf(),error='Inicia sesión desde un terminal registrado de la red de datos.'),403
    with db() as conn,conn.cursor() as cur:
        terminal_lock(cur)
        cur.execute("SELECT COUNT(*) AS n FROM auth_events WHERE terminal_ip=%s AND outcome='invalid' AND occurred_at>UTC_TIMESTAMP()-INTERVAL 15 MINUTE",(request.remote_addr,))
        if cur.fetchone()['n']>=8:
            return render_template('login.html',csrf=csrf(),error='Demasiados intentos fallidos. Espera 15 minutos.'),429
        cur.execute('SELECT id,password_hash,role_id,active FROM users WHERE username=%s',(username,))
        user=cur.fetchone()
        valid=check_password_hash(user['password_hash'] if user else previous.DUMMY_HASH,password)
        if not valid or not user or not user['active']:
            audit(cur,username,'invalid')
            return render_template('login.html',csrf=csrf(),error='Usuario o contraseña inválidos.'),401
        policy_sync()  # Fail before creating a new session when the adapter/controller is not ready.
        sw,port,mac,ip=HOSTS[client]; sid=secrets.token_urlsafe(32)
        # A terminal has one active network identity, even if two browsers are used.
        cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' WHERE terminal_ip=%s AND revoked_at IS NULL",(ip,))
        cur.execute('''INSERT INTO sessions(token_hash,user_id,role_id,created_at,expires_at,terminal_ip,
         terminal_mac,switch_dpid,in_port,network_state)
         VALUES(%s,%s,%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 15 MINUTE,%s,%s,%s,%s,'pending')''',
         (token_hash(sid),user['id'],user['role_id'],ip,mac,DPID[sw],port))
        try: policy_sync()
        except PolicyUnavailable:
            cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' WHERE token_hash=%s",(token_hash(sid),))
            audit(cur,username,'r1_failed'); raise
        audit(cur,username,'valid_r1')
    session.clear(); session.permanent=True; session['sid']=sid; session['csrf']=secrets.token_urlsafe(32)
    return redirect(url_for('panel'),code=303)

def panel():
    user=identity()
    if not user: return redirect(url_for('index'))
    policy_sync(); user=identity()
    if not user: return redirect(url_for('index'))
    with db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT x.code,x.label,x.ip_address,x.port,x.privileged,x.deployment_state,p.allowed
         FROM role_permissions p JOIN roles r ON p.role_id=r.id JOIN resources x ON p.resource_id=x.id
         WHERE r.code=%s ORDER BY x.id''',(user['role_code'],))
        resources=cur.fetchall()
    return render_template('panel.html',user=user,resources=resources,csrf=csrf())

def logout():
    token=session.get('sid')
    if token:
        with db() as conn,conn.cursor() as cur:
            terminal_lock(cur)
            cur.execute('''SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id
             WHERE s.token_hash=%s AND s.terminal_ip=%s''',(token_hash(token),request.remote_addr))
            row=cur.fetchone()
            cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' WHERE token_hash=%s AND terminal_ip=%s",(token_hash(token),request.remote_addr))
            if row: audit(cur,row['username'],'logout_r1')
            session.clear(); policy_sync()
    session.clear()
    return redirect(url_for('index'),code=303)

def health():
    with db() as conn,conn.cursor() as cur: cur.execute('SELECT 1'); cur.fetchone()
    policy_sync()
    return {'status':'ok','database':'mysql','step':5,'network_permissions_enabled':True,'scope':'R1 LMS HTTPS h1/h2'}

@app.errorhandler(PolicyUnavailable)
def policy_error(error):
    return render_template('error.html',message='El control SDN no está disponible. No se concede un nuevo permiso. Vuelve a intentar cuando se recupere.'),503

previous.identity=identity
app.view_functions.update(login=login,panel=panel,logout=logout,health=health)
