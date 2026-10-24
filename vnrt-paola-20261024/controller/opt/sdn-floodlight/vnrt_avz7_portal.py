"""Preserve passwords, CSRF, cookies and DTI; add observed binding and three-resource panel."""
from flask import redirect,render_template,request,url_for
import vnrt_portal_paso5 as portal
import vnrt_avz7_adapter as adapter
import vnrt_avz7_red as red
app=portal.app
original_login=portal.login

def identity():
    token=portal.session.get('sid')
    if not token:return None
    with portal.db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT u.id,u.username,u.display_name,r.label AS role_label,r.code AS role_code,
          s.network_state,s.terminal_ip,s.terminal_mac,s.switch_dpid,s.in_port,s.expires_at
          FROM sessions s JOIN users u ON s.user_id=u.id JOIN roles r ON r.id=u.role_id
          WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
          AND s.terminal_ip=%s AND u.active=TRUE AND s.role_id=u.role_id
          AND s.session_state='ACTIVE' AND s.enforcement_state='VERIFIED' ''',
          (portal.token_hash(token),request.remote_addr));user=cur.fetchone()
    if not user:portal.session.pop('sid',None)
    return user

def login():
    client=red.CLIENTS.get(request.remote_addr)
    if client:
        try:adapter.binding(client)
        except RuntimeError:
            return render_template('login.html',csrf=portal.csrf(),error='No se pudo validar la ubicación de red del terminal. No se concede acceso.'),503
    return original_login()

def panel():
    user=portal.identity()
    if not user:return redirect(url_for('index'))
    decisions=portal.policy_sync();user=portal.identity()
    if not user:return redirect(url_for('index'))
    with portal.db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT x.code,x.label,x.ip_address,x.port,x.privileged,x.deployment_state,p.allowed
          FROM role_permissions p JOIN roles r ON p.role_id=r.id JOIN resources x ON p.resource_id=x.id
          WHERE r.code=%s ORDER BY x.id''',(user['role_code'],));resources=cur.fetchall()
    states=decisions.get('resources',{}).get(red.CLIENTS[user['terminal_ip']],{})
    for resource in resources:resource['effective_state']=states.get(resource['code'],'pending')
    return render_template('panel.html',user=user,resources=resources,csrf=portal.csrf())

def health():
    with portal.db() as conn,conn.cursor() as cur:cur.execute('SELECT 1');cur.fetchone()
    result=portal.policy_sync()
    return {'status':'ok','database':'mysql','version':'AVZ7-20261010','network_permissions_enabled':True,
        'scope':'R1 sesiones; R2 LMS, Notas, Administración','metadata':True,'vlan':False,
        'actual_individual_rules':result.get('actual_individual_rules',0)}

app.view_functions.update(login=login,panel=panel,health=health)
portal.identity=identity
portal.previous.identity=identity
