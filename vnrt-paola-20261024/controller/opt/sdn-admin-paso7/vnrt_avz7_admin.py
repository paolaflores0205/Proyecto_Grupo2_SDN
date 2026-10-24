"""Keep DTI authentication; revoke one session and edit all three deployed resources."""
import re
from flask import abort,request,render_template
import vnrt_admin_paso7 as old
app=old.app
@old.authorized
def dashboard(user):
    with old.db() as conn,conn.cursor() as cur:
        cur.execute('SELECT u.id,u.username,u.display_name,u.active,u.role_id,r.label AS role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id');users=cur.fetchall()
        cur.execute('SELECT id,code,label FROM roles ORDER BY id');roles=cur.fetchall()
        cur.execute('''SELECT p.role_id,p.resource_id,p.allowed,r.label AS role,x.label AS resource,x.code,x.deployment_state
            FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id ORDER BY r.id,x.id''');policies=cur.fetchall()
        cur.execute('''SELECT s.token_hash AS session_id,s.user_id,u.username,s.terminal_ip,s.expires_at,s.session_state,s.enforcement_state
            FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6) ORDER BY s.created_at DESC''');sessions=cur.fetchall()
        cur.execute('SELECT occurred_at,actor,source_ip,action,target,before_json,after_json FROM admin_events ORDER BY id DESC LIMIT 100');events=cur.fetchall()
        cur.execute('SELECT occurred_at,username,terminal_ip,outcome FROM auth_events ORDER BY occurred_at DESC LIMIT 100');auth=cur.fetchall()
    return render_template('dashboard_avz7.html',user=user,users=users,roles=roles,policies=policies,sessions=sessions,events=events,auth=auth,csrf=old.csrf())
@old.authorized
def policy(user):
    try:role=int(request.form['role_id']);resource=int(request.form['resource_id'])
    except (ValueError,KeyError):abort(400)
    allowed=request.form.get('allowed');expected=request.form.get('expected')
    if allowed not in ('0','1') or expected not in ('0','1'):abort(400)
    with old.db() as conn,conn.cursor() as cur:
        conn.begin();cur.execute('SELECT allowed FROM role_permissions WHERE role_id=%s AND resource_id=%s FOR UPDATE',(role,resource))
        if not cur.fetchone():abort(400)
        cur.execute('''SELECT p.allowed,x.code,x.deployment_state,r.code AS role FROM role_permissions p JOIN resources x ON x.id=p.resource_id
          JOIN roles r ON r.id=p.role_id WHERE p.role_id=%s AND p.resource_id=%s''',(role,resource));row=cur.fetchone()
        if row['code'] not in ('lms','notas','administracion') or row['deployment_state']!='active':abort(400)
        if str(row['allowed'])!=expected:abort(409)
        cur.execute('UPDATE role_permissions SET allowed=%s WHERE role_id=%s AND resource_id=%s',(int(allowed),role,resource))
        old.event(cur,user['username'],'policy_change',row['role']+'/'+row['code'],{'allowed':bool(row['allowed'])},{'allowed':allowed=='1'});conn.commit()
    return old.applied(user)
@old.authorized
def revoke(user):
    sid=request.form.get('session_id','')
    if not re.fullmatch('[a-f0-9]{64}',sid):abort(400)
    with old.db() as conn,conn.cursor() as cur:
        conn.begin();cur.execute('SELECT terminal_ip,user_id FROM sessions WHERE token_hash=%s FOR UPDATE',(sid,));row=cur.fetchone()
        if not row:abort(404)
        cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked',session_state='REVOKED',enforcement_state='PENDING' WHERE token_hash=%s AND revoked_at IS NULL",(sid,))
        old.event(cur,user['username'],'session_revoke',row['terminal_ip'],None,{'revoked_count':cur.rowcount,'session_ref':sid[:16]});conn.commit()
    return old.applied(user)
app.view_functions.update(dashboard=dashboard,policy=policy,revoke=revoke)
