"""Single worker; fresh authorization snapshots with a monotonic database revision."""
import hashlib,json,time
from datetime import datetime,timezone
import vnrt_r1_paso5 as previous
import vnrt_avz7_adapter as old
import vnrt_mt_red as red
db=previous.db;binding=old.binding

def snapshot(cur):
    cur.execute('SELECT revision FROM policy_revision WHERE id=1');revision=cur.fetchone()['revision']
    cur.execute('''SELECT s.token_hash,s.user_id,s.role_id,s.created_at,s.expires_at,s.terminal_ip,s.terminal_mac,
        s.switch_dpid,s.in_port,u.active,u.role_id AS current_role,r.code AS role_code
        FROM sessions s JOIN users u ON u.id=s.user_id JOIN roles r ON r.id=u.role_id
        WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
        ORDER BY s.created_at DESC''');sessions=cur.fetchall()
    cur.execute('''SELECT p.role_id,p.allowed,x.code,x.ip_address,x.port,x.transport,x.deployment_state
        FROM role_permissions p JOIN resources x ON x.id=p.resource_id ORDER BY p.role_id,x.code''');policies=cur.fetchall()
    digest=hashlib.sha256(json.dumps([sessions,policies],sort_keys=True,default=str).encode()).hexdigest()
    cur.execute('SELECT revision FROM policy_revision WHERE id=1')
    if cur.fetchone()['revision']!=revision:raise RuntimeError('Authorization changed during snapshot')
    return revision,digest,sessions,policies

class Reconciler:
    def __init__(self):self.current={}
    def sync(self):
        with db() as conn,conn.cursor() as cur:
            cur.execute("SELECT GET_LOCK('sdn-mt-worker',2) AS locked")
            if cur.fetchone()['locked']!=1:raise RuntimeError('Another worker owns enforcement')
            try:return self.enforce(cur)
            finally:cur.execute("SELECT RELEASE_LOCK('sdn-mt-worker')")
    def enforce(self,cur):
        if not {f['name'] for f in red.baseline()}.issubset(red.stored_names()):raise RuntimeError('Baseline unavailable')
        if {r['switchDPID'] for r in red.api('/wm/core/controller/switches/json')}!=set(red.DPID.values()):raise RuntimeError('Switch unavailable')
        revision,digest,rows,policy_rows=snapshot(cur)
        policies={(p['role_id'],p['code']):p for p in policy_rows};devices=red.api('/wm/device/')
        wanted=[];decisions={};tokens={};links={};plans={};contexts=set()
        for row in rows:
            client=red.CLIENTS.get(row['terminal_ip'])
            if not client or client in decisions or not row['active'] or row['role_id']!=row['current_role']:continue
            try:b=binding(client,devices)
            except RuntimeError:continue
            if (row['terminal_mac'],row['switch_dpid'],row['in_port'])!=(b['mac'],b['dpid'],b['port']):continue
            seconds=min(30,int((row['expires_at']-datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())-2)
            if seconds<=0:continue
            states={}
            for code,(server,port) in red.SPEC.items():
                p=policies.get((row['current_role'],code))
                allowed=bool(p and p['allowed'] and p['deployment_state']=='active' and p['transport']=='TCP'
                             and p['ip_address']==red.HOSTS[server][3] and p['port']==port)
                states[code]='active' if allowed else 'denied'
            sid=row['token_hash'];role=row['role_code'];lms=states['lms']=='active'
            ctx=red.context(sid,role,lms)
            if ctx in contexts:raise RuntimeError('Session metadata collision')
            contexts.add(ctx)
            group=red.session_rules(client,seconds,sid,role,lms)
            for f in group:links[f['name']]=(sid,'session')
            for code in red.SPEC:
                if states[code]=='active':
                    for f in red.permissions(client,code,seconds,sid,role,lms):
                        group.append(f);links[f['name']]=(sid,code)
            signature=(sid,role,tuple(states.items()))
            plans[client]=(signature,group);wanted+=group;tokens[client]=sid;decisions[client]=states
        def guard():
            fresh=snapshot(cur)
            if fresh[0]!=revision or fresh[1]!=digest:raise RuntimeError('Stale authorization revision rejected')
        invalid=[r['token_hash'] for r in rows if r['token_hash'] not in set(tokens.values())]
        if invalid:
            guard()
            cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked',session_state='REVOKED',enforcement_state='PENDING' WHERE revoked_at IS NULL AND token_hash IN ("+','.join(['%s']*len(invalid))+")",tuple(invalid))
            raise RuntimeError('Invalid binding/account/session retired; re-evaluation required')
        # A socket request contains only "sync", never a cached grant to replay later.
        guard();present=red.stored_names();expected={f['name'] for f in wanted}
        red.remove([n for n in present if n.startswith((red.P+'session-',red.P+'grant-')) and n not in expected])
        for client,(signature,group) in plans.items():
            prior=self.current.get(client);names={f['name'] for f in group}
            due=not prior or prior[0]!=signature or time.monotonic()-prior[1]>=10 or not names.issubset(present)
            if due:
                guard()
                # Explicit ADD after retirement resets the finite lease reliably in this Floodlight build.
                red.remove([n for n in present if n.startswith((red.P+'session-',red.P+'grant-')) and '-'+client+'-' in n])
                for f in sorted(group,key=lambda f:0 if f['switch']==red.DPID['sw3'] else 1 if f['table']=='30' else 2 if f['table']=='20' else 3):
                    guard();red.push(f)
                self.current[client]=(signature,time.monotonic())
        observed=red.verify_actual(wanted)
        actual_count=sum(red.number(r['priority'])==500 for rules in observed.values() for r in rules)
        if actual_count!=len(wanted):raise RuntimeError('Unexpected session rules')
        guard()
        for client in decisions:binding(client)
        guard()
        cur.execute("UPDATE sessions SET session_state='EXPIRED',network_state='revoked',enforcement_state='VERIFIED' WHERE revoked_at IS NULL AND expires_at<=UTC_TIMESTAMP(6)")
        cur.execute("UPDATE sessions SET session_state='REVOKED',network_state='revoked',enforcement_state='VERIFIED' WHERE revoked_at IS NOT NULL")
        for client,sid in tokens.items():
            state='active' if any(v=='active' for v in decisions[client].values()) else 'denied'
            cur.execute("UPDATE sessions SET session_state='ACTIVE',network_state=%s,enforcement_state='VERIFIED' WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)",(state,sid))
        cur.execute("UPDATE network_rules SET enforcement_state='RETIRED' WHERE enforcement_state IN ('VERIFIED','PENDING_RETIRE')")
        for f in wanted:
            sid,code=links[f['name']];record=dict(f,authorization_revision=revision)
            cur.execute('''INSERT INTO network_rules(rule_name,session_id,resource_code,switch_dpid,rule_json,enforcement_state,updated_at)
                VALUES(%s,%s,%s,%s,%s,'VERIFIED',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE rule_json=VALUES(rule_json),enforcement_state='VERIFIED',updated_at=UTC_TIMESTAMP(6)''',
                (f['name'],sid,code,f['switch'],json.dumps(record)))
        guard()
        self.current={k:v for k,v in self.current.items() if k in plans}
        return {'ok':True,'terminals':{c:'active' if any(v=='active' for v in s.values()) else 'denied' for c,s in decisions.items()},
                'resources':decisions,'actual_individual_rules':len(wanted),'session_rules':4*len(plans),
                'r2_rules':len(wanted)-4*len(plans),'baseline_rules':len(red.baseline()),'authorization_revision':revision,'metadata':True}
    def fail_closed(self):
        self.current.clear()
        try:red.remove([n for n in red.stored_names() if n.startswith((red.P+'session-',red.P+'grant-'))])
        except Exception:pass
        try:
            with db() as conn,conn.cursor() as cur:
                cur.execute("UPDATE sessions SET enforcement_state='FAILED' WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)")
                cur.execute("UPDATE network_rules SET enforcement_state='PENDING_RETIRE' WHERE enforcement_state='VERIFIED'")
        except Exception:pass

def daemon():previous.Reconciler=Reconciler;previous.daemon()
if __name__=='__main__':daemon()
