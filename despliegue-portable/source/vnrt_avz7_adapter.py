"""Session/resource-scoped, verified grants. Python outside Floodlight; no metadata."""
import argparse, json, time
from datetime import datetime,timezone
from pathlib import Path
import vnrt_r1_paso5 as previous
import vnrt_avz7_red as red
db=previous.db;LEASE=30

def binding(client,devices=None):
    sw,port,mac,ip=red.HOSTS[client]
    devices=red.api('/wm/device/') if devices is None else devices
    matches=[]
    for d in devices:
        if ip in d.get('ipv4',[]) and mac in [m.lower() for m in d.get('mac',[])]:
            for a in d.get('attachmentPoint',[]):
                dp=a.get('switchDPID',a.get('switch'));p=red.normal('in_port',a.get('port'))
                if not a.get('errorStatus') and (dp,p)==(red.DPID[sw],port):matches.append(d)
    if len(matches)!=1:raise RuntimeError('Observed terminal binding missing or ambiguous')
    # A different MAC reporting the same IP is an ambiguity, not a second identity.
    if any(ip in d.get('ipv4',[]) and mac not in [m.lower() for m in d.get('mac',[])] for d in devices):
        raise RuntimeError('Observed IP conflict')
    return {'mac':mac,'ip':ip,'dpid':red.DPID[sw],'port':port}

class Reconciler:
    def __init__(self):self.current={}
    def sync(self):
        present=red.stored_names();base={f['name'] for f in red.baseline()}
        if not base.issubset(present):raise RuntimeError('Restrictive baseline unavailable')
        if {s['switchDPID'] for s in red.api('/wm/core/controller/switches/json')}!=set(red.DPID.values()):
            raise RuntimeError('Switch disconnected')
        devices=red.api('/wm/device/');desired={};wanted=[];decisions={};token_for={}
        with db() as conn,conn.cursor() as cur:
            cur.execute('''SELECT s.*,u.active,u.role_id AS current_role FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
                AND s.network_state IN ('pending','active','denied') ORDER BY s.created_at DESC''')
            for row in cur.fetchall():
                client=red.CLIENTS.get(row['terminal_ip'])
                if not client or client in desired:continue
                if not row['active'] or row['role_id']!=row['current_role']:continue
                try:b=binding(client,devices)
                except RuntimeError:continue
                if (row['terminal_mac'],row['switch_dpid'],row['in_port'])!=(b['mac'],b['dpid'],b['port']):continue
                remaining=int((row['expires_at']-datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())
                if remaining>0:desired[client]=(row,min(remaining,LEASE))
            cur.execute('''SELECT p.role_id,p.allowed,x.code,x.ip_address,x.port,x.transport,x.deployment_state
                FROM role_permissions p JOIN resources x ON x.id=p.resource_id''')
            policies={(p['role_id'],p['code']):p for p in cur.fetchall()}
            expected=set()
            for client in red.CLIENTS.values():
                item=desired.get(client);states={}
                for code,(server,port) in red.SPEC.items():
                    pol=policies.get((item[0]['current_role'],code)) if item else None
                    allowed=bool(pol and pol['allowed'] and pol['deployment_state']=='active'
                        and pol['ip_address']==red.HOSTS[server][3] and pol['port']==port and pol['transport']=='TCP')
                    sid=item[0]['token_hash'] if item else None
                    rules=red.permissions(client,code,item[1],sid) if allowed else []
                    names={f['name'] for f in rules};expected|=names;wanted+=rules
                    signature=(sid,allowed);prior=self.current.get((client,code))
                    due=not prior or prior[:2]!=signature or (allowed and time.monotonic()-prior[2]>=10) or not names.issubset(present)
                    if due:
                        # No session grant can be installed until its policy has been validated.
                        stale=[n for n in present if n.startswith(red.P+'grant-') and '-'+client+'-'+code+'-' in n]
                        red.remove(stale)
                        if allowed:
                            for f in rules:red.push(f)
                        self.current[(client,code)]=(*signature,time.monotonic())
                    states[code]='active' if allowed else 'denied'
                if item:decisions[client]=states;token_for[client]=sid
            stale={n for n in red.stored_names() if n.startswith(red.P+'grant-')}-expected
            red.remove(stale)
            # Check actual dataplane, not only the pusher's database.
            until=time.monotonic()+4
            while True:
                observed=red.verify_actual(wanted)
                count=sum(int(r['priority'])==500 for rows in observed.values() for r in rows)
                if count==len(wanted):break
                if time.monotonic()>until:raise RuntimeError('Unexpected or stale permission in dataplane')
                time.sleep(.2)
            cur.execute("UPDATE sessions SET session_state='EXPIRED',network_state='revoked',enforcement_state='VERIFIED' WHERE revoked_at IS NULL AND expires_at<=UTC_TIMESTAMP(6)")
            cur.execute("UPDATE sessions SET session_state='REVOKED',enforcement_state='VERIFIED' WHERE revoked_at IS NOT NULL")
            validtokens=set(token_for.values())
            for client,(row,_) in desired.items():
                state='active' if any(v=='active' for v in decisions[client].values()) else 'denied'
                cur.execute("UPDATE sessions SET session_state='ACTIVE',network_state=%s,enforcement_state='VERIFIED' WHERE token_hash=%s",(state,row['token_hash']))
            cur.execute("UPDATE sessions SET revoked_at=UTC_TIMESTAMP(6),network_state='revoked',session_state='REVOKED',enforcement_state='VERIFIED' WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6) AND network_state IN ('pending','active','denied')"+(' AND token_hash NOT IN ('+','.join(['%s']*len(validtokens))+')' if validtokens else ''),tuple(validtokens))
            # Persist rule/session linkage for isolated revocation and quantitative reporting.
            cur.execute("UPDATE network_rules SET enforcement_state='RETIRED' WHERE enforcement_state IN ('VERIFIED','PENDING_RETIRE')")
            for f in wanted:
                sid=next(token for token in validtokens if token[:16] in f['name'])
                code=next(code for code in red.SPEC if '-'+code+'-' in f['name'])
                cur.execute('''INSERT INTO network_rules(rule_name,session_id,resource_code,switch_dpid,rule_json,enforcement_state,updated_at)
                    VALUES(%s,%s,%s,%s,%s,'VERIFIED',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE
                    rule_json=VALUES(rule_json),enforcement_state='VERIFIED',updated_at=UTC_TIMESTAMP(6)''',
                    (f['name'],sid,code,f['switch'],json.dumps(f)))
        return {'ok':True,'terminals':{c:('active' if any(v=='active' for v in s.values()) else 'denied') for c,s in decisions.items()},
            'resources':decisions,'actual_individual_rules':len(wanted),'baseline_rules':len(red.baseline())}
    def fail_closed(self):
        self.current.clear()
        try:red.remove([n for n in red.stored_names() if n.startswith(red.P+'grant-')])
        except Exception:pass # Switch leases expire within 30s if the controller is unavailable.
        try:
            with db() as conn,conn.cursor() as cur:
                cur.execute("UPDATE sessions SET enforcement_state='FAILED' WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)")
                cur.execute("UPDATE network_rules SET enforcement_state='PENDING_RETIRE' WHERE enforcement_state='VERIFIED'")
        except Exception:pass

def daemon():previous.Reconciler=Reconciler;previous.daemon()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['daemon','bootstrap','verify']);a=p.parse_args().action
    if a=='daemon':daemon()
    elif a=='bootstrap':red.bootstrap()
    else:red.verify_actual(red.baseline());print('VERIFIED')
