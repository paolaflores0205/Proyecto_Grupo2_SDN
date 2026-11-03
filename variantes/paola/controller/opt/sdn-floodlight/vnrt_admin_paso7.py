#!/usr/bin/env python3
"""DTI management on the management interface, separate identity from campus roles."""
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import socket
from flask import Flask, abort, redirect, render_template, request, session, url_for
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash

CONFIG=json.loads(Path('/etc/sdn-admin-paso7/config.json').read_text())
app=Flask(__name__)
app.config.update(SECRET_KEY=CONFIG['secret_key'],SESSION_COOKIE_NAME='sdn_dti',
 SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
 PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),MAX_CONTENT_LENGTH=4096)
DUMMY=generate_password_hash(secrets.token_urlsafe(24),method='scrypt')

def db():
    return pymysql.connect(host='127.0.0.1',port=3306,user=CONFIG['db_user'],password=CONFIG['db_password'],
     database='sdn_g2',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,
     autocommit=True,connect_timeout=3,read_timeout=3,write_timeout=3)

def digest(value): return hashlib.sha256(value.encode()).hexdigest()

def csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
    return session['csrf']

def event(cur,actor,action,target='',before=None,after=None):
    cur.execute('''INSERT INTO admin_events(occurred_at,actor,source_ip,action,target,before_json,after_json)
     VALUES(UTC_TIMESTAMP(6),%s,%s,%s,%s,%s,%s)''',
     (actor[:64],request.remote_addr[:45],action,target[:100],
      None if before is None else json.dumps(before),None if after is None else json.dumps(after)))

def identity():
    token=session.get('aid')
    if not token: return None
    with db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT a.id,a.username,s.expires_at FROM admin_sessions s
         JOIN admin_accounts a ON a.id=s.admin_id WHERE s.token_hash=%s AND s.source_ip=%s
         AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6) AND a.active=TRUE''',
         (digest(token),request.remote_addr))
        user=cur.fetchone()
    if not user: session.pop('aid',None)
    return user

def authorized(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        user=identity()
        if not user:
            if request.method=='POST': abort(403)
            return redirect(url_for('index'))
        return fn(user,*args,**kwargs)
    return wrapped

@app.before_request
def protect():
    if request.method=='POST':
        supplied=request.form.get('csrf','')
        if not supplied or not hmac.compare_digest(session.get('csrf',''),supplied): abort(400)

@app.after_request
def headers(response):
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
     'X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
    return response

def sync():
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(12); connection.connect('/run/sdn-r1/policy.sock')
        connection.sendall(b'{"action":"sync"}\n'); output=b''
        while not output.endswith(b'\n'):
            part=connection.recv(4096)
            if not part or len(output)>65536: raise RuntimeError('Invalid adapter response')
            output+=part
    if not json.loads(output).get('ok'): raise RuntimeError('Policy synchronization failed')

def applied(user):
    try:
        sync()
    except Exception:
        with db() as conn,conn.cursor() as cur: event(cur,user['username'],'sync_failed','R1/R2')
        return render_template('message.html',title='Cambio guardado; sincronización pendiente',
         message='MySQL guardó el cambio, pero no se confirmó su aplicación en los switches. No se afirma que el acceso cambió inmediatamente. Los permisos existentes caducan en un máximo de 30 segundos sin renovación; revise el adaptador.'),503
    return redirect(url_for('dashboard'),code=303)

@app.get('/')
def index():
    if identity(): return redirect(url_for('dashboard'))
    return render_template('login.html',csrf=csrf(),error=None)

@app.post('/login')
def login():
    username=request.form.get('username','').strip().lower(); password=request.form.get('password','')
    if not re.fullmatch(r'[a-z0-9_]{1,64}',username) or not 1<=len(password)<=256: abort(400)
    with db() as conn,conn.cursor() as cur:
        # Serialize rate-limit check and insert, including concurrent login attempts.
        cur.execute('SELECT GET_LOCK(%s,5) AS locked',('sdn-dti-login-'+request.remote_addr,))
        if cur.fetchone()['locked']!=1: abort(503)
        cur.execute("SELECT COUNT(*) AS n FROM admin_events WHERE source_ip=%s AND action='login_invalid' AND occurred_at>UTC_TIMESTAMP()-INTERVAL 15 MINUTE",(request.remote_addr,))
        if cur.fetchone()['n']>=8: abort(429)
        cur.execute('SELECT id,username,password_hash,active FROM admin_accounts WHERE username=%s',(username,))
        user=cur.fetchone(); valid=check_password_hash(user['password_hash'] if user else DUMMY,password)
        if not valid or not user or not user['active']:
            event(cur,username,'login_invalid')
            return render_template('login.html',csrf=csrf(),error='Credenciales DTI inválidas.'),401
        if session.get('aid'): cur.execute('UPDATE admin_sessions SET revoked_at=UTC_TIMESTAMP(6) WHERE token_hash=%s',(digest(session['aid']),))
        token=secrets.token_urlsafe(32)
        cur.execute('''INSERT INTO admin_sessions(token_hash,admin_id,source_ip,created_at,expires_at)
         VALUES(%s,%s,%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 10 MINUTE)''',(digest(token),user['id'],request.remote_addr))
        event(cur,user['username'],'login_valid')
    session.clear(); session.permanent=True; session['aid']=token; session['csrf']=secrets.token_urlsafe(32)
    return redirect(url_for('dashboard'),code=303)

@app.get('/dashboard')
@authorized
def dashboard(user):
    with db() as conn,conn.cursor() as cur:
        cur.execute('SELECT u.id,u.username,u.display_name,u.active,u.role_id,r.label AS role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id'); users=cur.fetchall()
        cur.execute('SELECT id,code,label FROM roles ORDER BY id'); roles=cur.fetchall()
        cur.execute('''SELECT p.role_id,p.resource_id,p.allowed,r.label AS role,x.label AS resource,x.code,x.deployment_state
         FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id ORDER BY r.id,x.id'''); policies=cur.fetchall()
        cur.execute('''SELECT s.user_id,u.username,s.terminal_ip,s.expires_at,s.network_state FROM sessions s JOIN users u ON u.id=s.user_id
         WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6) ORDER BY s.created_at DESC'''); sessions=cur.fetchall()
        cur.execute('SELECT occurred_at,actor,source_ip,action,target,before_json,after_json FROM admin_events ORDER BY id DESC LIMIT 100'); events=cur.fetchall()
        cur.execute('SELECT occurred_at,username,terminal_ip,outcome FROM auth_events ORDER BY occurred_at DESC LIMIT 100'); auth=cur.fetchall()
    return render_template('dashboard.html',user=user,users=users,roles=roles,policies=policies,
     sessions=sessions,events=events,auth=auth,csrf=csrf())

@app.post('/policy')
@authorized
def policy(user):
    try: role=int(request.form['role_id']); resource=int(request.form['resource_id'])
    except (ValueError,KeyError): abort(400)
    allowed=request.form.get('allowed'); expected=request.form.get('expected')
    if allowed not in ('0','1') or expected not in ('0','1'): abort(400)
    with db() as conn,conn.cursor() as cur:
        conn.begin()
        # Lock only the editable policy row, not read-only role/resource catalogs.
        cur.execute('SELECT allowed FROM role_permissions WHERE role_id=%s AND resource_id=%s FOR UPDATE',(role,resource))
        if not cur.fetchone(): abort(400)
        cur.execute('''SELECT p.allowed,x.code,x.deployment_state,r.code AS role FROM role_permissions p
         JOIN resources x ON x.id=p.resource_id JOIN roles r ON r.id=p.role_id
         WHERE p.role_id=%s AND p.resource_id=%s''',(role,resource)); row=cur.fetchone()
        if not row or row['code'] not in ('lms','notas') or row['deployment_state']!='active': abort(400)
        if str(row['allowed'])!=expected: abort(409)
        cur.execute('UPDATE role_permissions SET allowed=%s WHERE role_id=%s AND resource_id=%s',(int(allowed),role,resource))
        event(cur,user['username'],'policy_change',row['role']+'/'+row['code'],{'allowed':bool(row['allowed'])},{'allowed':allowed=='1'})
        conn.commit()
    return applied(user)

@app.post('/user')
@authorized
def change_user(user):
    try: uid=int(request.form['user_id']); role=int(request.form['role_id']); old_role=int(request.form['expected_role'])
    except (ValueError,KeyError): abort(400)
    active=request.form.get('active'); expected=request.form.get('expected_active')
    if active not in ('0','1') or expected not in ('0','1'): abort(400)
    with db() as conn,conn.cursor() as cur:
        conn.begin(); cur.execute('SELECT id FROM roles WHERE id=%s',(role,))
        if not cur.fetchone(): abort(400)
        cur.execute('SELECT username,role_id,active FROM users WHERE id=%s FOR UPDATE',(uid,)); row=cur.fetchone()
        if not row: abort(404)
        if row['role_id']!=old_role or str(row['active'])!=expected: abort(409)
        cur.execute('UPDATE users SET role_id=%s,active=%s WHERE id=%s',(role,int(active),uid))
        # A changed identity must reauthenticate; never silently elevate a live session.
        cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' WHERE user_id=%s AND revoked_at IS NULL",(uid,))
        event(cur,user['username'],'user_change',row['username'],{'role_id':row['role_id'],'active':bool(row['active'])},{'role_id':role,'active':active=='1'})
        conn.commit()
    return applied(user)

@app.post('/revoke')
@authorized
def revoke(user):
    try: uid=int(request.form['user_id'])
    except (ValueError,KeyError): abort(400)
    with db() as conn,conn.cursor() as cur:
        conn.begin(); cur.execute('SELECT username FROM users WHERE id=%s FOR UPDATE',(uid,)); row=cur.fetchone()
        if not row: abort(404)
        cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked' WHERE user_id=%s AND revoked_at IS NULL",(uid,))
        event(cur,user['username'],'sessions_revoke',row['username'],None,{'revoked_count':cur.rowcount}); conn.commit()
    return applied(user)

@app.post('/logout')
@authorized
def logout(user):
    with db() as conn,conn.cursor() as cur:
        cur.execute('UPDATE admin_sessions SET revoked_at=UTC_TIMESTAMP(6) WHERE token_hash=%s',(digest(session['aid']),))
        event(cur,user['username'],'logout')
    session.clear(); return redirect(url_for('index'),code=303)

@app.get('/health')
def health():
    with db() as conn,conn.cursor() as cur: cur.execute('SELECT 1'); cur.fetchone()
    return {'status':'ok','step':7,'service':'DTI administration','scope':'management network only'}

@app.errorhandler(pymysql.MySQLError)
def database_error(error):
    app.logger.error('DTI database unavailable; operation denied')
    return render_template('message.html',title='Repositorio no disponible',message='No se confirmó ningún cambio. Revise MySQL y vuelva a consultar el estado antes de repetirlo.'),503

for status,title,message in [(400,'Solicitud inválida','Vuelve al formulario y revisa los datos.'),
 (403,'Acceso denegado','Debes autenticarte con una cuenta DTI.'),(404,'No encontrado','El elemento no existe.'),
 (409,'Datos desactualizados','Otro cambio modificó este registro. Recarga el panel antes de editar.'),
 (413,'Solicitud demasiado grande','No se procesó el formulario.'),(429,'Demasiados intentos','Espera 15 minutos antes de intentar otra vez.'),
 (503,'Servicio no disponible','Vuelve a consultar el estado antes de repetir una operación.')]:
    def handle(error,code=status,title=title,message=message): return render_template('message.html',title=title,message=message),code
    app.register_error_handler(status,handle)
