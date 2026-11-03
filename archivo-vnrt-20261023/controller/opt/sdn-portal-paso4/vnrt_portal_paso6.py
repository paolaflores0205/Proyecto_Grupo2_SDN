#!/usr/bin/env python3
"""Keep step5 authentication; show the distinct effective R1/R2 resource decisions."""
from flask import redirect,render_template,url_for
import vnrt_portal_paso5 as portal
from vnrt_r1_r2_paso6 import CLIENTS
app=portal.app

def panel():
    user=portal.identity()
    if not user: return redirect(url_for('index'))
    decisions=portal.policy_sync(); user=portal.identity()
    if not user: return redirect(url_for('index'))
    with portal.db() as conn,conn.cursor() as cur:
        cur.execute('''SELECT x.code,x.label,x.ip_address,x.port,x.privileged,x.deployment_state,p.allowed
         FROM role_permissions p JOIN roles r ON p.role_id=r.id JOIN resources x ON p.resource_id=x.id
         WHERE r.code=%s ORDER BY x.id''',(user['role_code'],))
        resources=cur.fetchall()
    states=decisions.get('resources',{}).get(CLIENTS[user['terminal_ip']],{})
    for resource in resources: resource['effective_state']=states.get(resource['code'],'pending')
    return render_template('panel.html',user=user,resources=resources,csrf=portal.csrf())

def health():
    with portal.db() as conn,conn.cursor() as cur: cur.execute('SELECT 1'); cur.fetchone()
    portal.policy_sync()
    return {'status':'ok','database':'mysql','step':6,'network_permissions_enabled':True,'scope':'R1 LMS + R2 notas HTTPS h1/h2'}

app.view_functions.update(panel=panel,health=health)
