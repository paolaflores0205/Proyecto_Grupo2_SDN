"""Keep existing portal, credentials, CSRF and cookies; report the active pipeline."""
from flask import request
import vnrt_avz7_portal as original
app=original.app
def identity():
    token=original.portal.session.get('sid')
    if not token:return None
    def read():
        with original.portal.db() as conn,conn.cursor() as cur:
            cur.execute('''SELECT u.id,u.username,u.display_name,r.label AS role_label,r.code AS role_code,
                s.network_state,s.terminal_ip,s.terminal_mac,s.switch_dpid,s.in_port,s.expires_at,
                s.session_state,s.enforcement_state FROM sessions s JOIN users u ON s.user_id=u.id
                JOIN roles r ON r.id=u.role_id WHERE s.token_hash=%s AND s.revoked_at IS NULL
                AND s.expires_at>UTC_TIMESTAMP(6) AND s.terminal_ip=%s AND u.active=TRUE AND s.role_id=u.role_id''',
                (original.portal.token_hash(token),request.remote_addr))
            return cur.fetchone()
    user=read()
    if not user:
        original.portal.session.pop('sid',None);return None
    if user['session_state']!='ACTIVE' or user['enforcement_state']!='VERIFIED':
        # A transient enforcement failure is not logout; preserve the valid cookie.
        original.portal.policy_sync();user=read()
        if not user:
            original.portal.session.pop('sid',None);return None
        if user['session_state']!='ACTIVE' or user['enforcement_state']!='VERIFIED':raise original.portal.PolicyUnavailable()
    return user
original.portal.identity=identity
original.portal.previous.identity=identity
def health():
    result=original.portal.policy_sync()
    return dict(status='ok',database='mysql',version='MULTITABLE-20261021',metadata=True,vlan=False,
                tables_sw2=[0,10,20,30],network_permissions_enabled=True,scope='R1 LMS; R2 Notas, Administración',
                **{k:result.get(k,0) for k in ['actual_individual_rules','session_rules','r2_rules','baseline_rules','authorization_revision']})
app.view_functions['health']=health
