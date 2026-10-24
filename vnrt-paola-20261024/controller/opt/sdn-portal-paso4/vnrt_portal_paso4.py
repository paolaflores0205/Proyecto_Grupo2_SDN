#!/usr/bin/env python3
"""Portal identity verification only. No Floodlight client or network grants."""
from datetime import timedelta
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
from flask import Flask, abort, redirect, render_template, request, session, url_for
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash

CONFIG=json.loads(Path('/etc/sdn-portal-paso4/config.json').read_text())
app=Flask(__name__)
app.config.update(SECRET_KEY=CONFIG['secret_key'],SESSION_COOKIE_NAME='sdn_portal',
 SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
 PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),MAX_CONTENT_LENGTH=4096)
DUMMY_HASH=generate_password_hash(secrets.token_urlsafe(24),method='scrypt')

def db():
    return pymysql.connect(host='127.0.0.1',port=3306,user=CONFIG['db_user'],
     password=CONFIG['db_password'],database='sdn_g2',charset='utf8mb4',
     cursorclass=pymysql.cursors.DictCursor,autocommit=True,
     connect_timeout=3,read_timeout=3,write_timeout=3)

def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()

def csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
    return session['csrf']

@app.before_request
def protect_forms():
    if request.method=='POST':
        given=request.form.get('csrf','')
        if not given or not hmac.compare_digest(session.get('csrf',''),given): abort(400)

@app.after_request
def headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response

def identity():
    token=session.get('sid')
    if not token: return None
    with db() as connection,connection.cursor() as cursor:
        cursor.execute('''SELECT u.id,u.username,u.display_name,r.label AS role_label,r.code AS role_code
         FROM sessions s JOIN users u ON s.user_id=u.id JOIN roles r ON u.role_id=r.id
         WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
         AND u.active=TRUE AND s.role_id=u.role_id AND s.network_state='not_applied' ''',(token_hash(token),))
        user=cursor.fetchone()
    if not user: session.pop('sid',None)
    return user

def audit(cursor,username,outcome):
    cursor.execute('INSERT INTO auth_events(occurred_at,username,terminal_ip,outcome) VALUES(UTC_TIMESTAMP(6),%s,%s,%s)',
     (username[:64],request.remote_addr[:45],outcome))

@app.get('/')
def index():
    if identity(): return redirect(url_for('panel'))
    return render_template('login.html',csrf=csrf(),error=None)

@app.post('/login')
def login():
    username=request.form.get('username','').strip().lower()
    password=request.form.get('password','')
    if not re.fullmatch(r'[a-z0-9_]{1,64}',username) or not 1<=len(password)<=256:
        return render_template('login.html',csrf=csrf(),error='Usuario o contraseña inválidos.'),401
    with db() as connection,connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM auth_events WHERE terminal_ip=%s AND outcome='invalid' AND occurred_at>UTC_TIMESTAMP()-INTERVAL 15 MINUTE",(request.remote_addr,))
        if cursor.fetchone()['n']>=8:
            return render_template('login.html',csrf=csrf(),error='Demasiados intentos fallidos. Espera 15 minutos.'),429
        cursor.execute('SELECT id,password_hash,role_id,active FROM users WHERE username=%s',(username,))
        user=cursor.fetchone()
        valid=check_password_hash(user['password_hash'] if user else DUMMY_HASH,password)
        if not valid or not user or not user['active']:
            audit(cursor,username,'invalid')
            return render_template('login.html',csrf=csrf(),error='Usuario o contraseña inválidos.'),401
        if session.get('sid'):
            cursor.execute('UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6) WHERE token_hash=%s',(token_hash(session['sid']),))
        sid=secrets.token_urlsafe(32)
        cursor.execute('''INSERT INTO sessions(token_hash,user_id,role_id,created_at,expires_at,terminal_ip,network_state)
         VALUES(%s,%s,%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 15 MINUTE,%s,'not_applied')''',
         (token_hash(sid),user['id'],user['role_id'],request.remote_addr))
        audit(cursor,username,'valid_portal_only')
    session.clear(); session.permanent=True
    session['sid']=sid; session['csrf']=secrets.token_urlsafe(32)
    return redirect(url_for('panel'),code=303)

@app.get('/panel')
def panel():
    user=identity()
    if not user: return redirect(url_for('index'))
    with db() as connection,connection.cursor() as cursor:
        cursor.execute('''SELECT x.label,x.ip_address,x.port,x.privileged,x.deployment_state,p.allowed
         FROM role_permissions p JOIN roles r ON p.role_id=r.id JOIN resources x ON p.resource_id=x.id
         WHERE r.code=%s ORDER BY x.id''',(user['role_code'],))
        resources=cursor.fetchall()
    return render_template('panel.html',user=user,resources=resources,csrf=csrf())

@app.post('/logout')
def logout():
    user=identity()
    if session.get('sid'):
        with db() as connection,connection.cursor() as cursor:
            cursor.execute('UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6) WHERE token_hash=%s',(token_hash(session['sid']),))
            if user: audit(cursor,user['username'],'logout_portal_only')
    session.clear()
    return redirect(url_for('index'),code=303)

@app.get('/health')
def health():
    with db() as connection,connection.cursor() as cursor:
        cursor.execute('SELECT 1'); cursor.fetchone()
    return {'status':'ok','database':'mysql','step':4,'network_permissions_enabled':False}

@app.errorhandler(pymysql.MySQLError)
def database_error(error):
    app.logger.error('Database unavailable; portal denied request')
    return render_template('error.html',message='El repositorio no está disponible. No se concede acceso.'),503

@app.errorhandler(400)
def bad_request(error): return render_template('error.html',message='Solicitud inválida. Vuelve al formulario e inténtalo otra vez.'),400

@app.errorhandler(413)
def too_large(error): return render_template('error.html',message='La solicitud excede el tamaño permitido.'),413
