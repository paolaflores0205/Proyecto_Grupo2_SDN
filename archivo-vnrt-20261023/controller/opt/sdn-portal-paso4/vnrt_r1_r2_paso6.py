#!/usr/bin/env python3
"""Resource-scoped R1/R2 adapter. Same trusted terminal inventory and UNIX socket as step5."""
import argparse
from datetime import datetime, timezone
import time
import vnrt_r1_paso5 as old
api=old.api; DPID=old.DPID; HOSTS=old.HOSTS; ADJ=old.ADJ; path=old.path
CLIENTS=old.CLIENTS; LEASE=old.LEASE; db=old.db; push=old.push; remove=old.remove
stored_names=old.stored_names; base_names=old.base_names; portal_flows=old.portal_flows
SPEC={'lms':{'host':'h3','prefix':'g2-p5-','allow_priority':450},
      'notas':{'host':'h4','prefix':'g2-p6-','allow_priority':470}}

def notes_guards():
    result=[]; server=HOSTS['h4']
    for client in CLIENTS.values():
        sw,port,mac,ip=HOSTS[client]
        result.append({'switch':DPID[sw],'name':'g2-p6-deny-'+client,'priority':'420','active':'true',
         'in_port':str(port),'eth_type':'0x0800','ip_proto':'6','ipv4_dst':server[3]+'/32','tcp_dst':'443','actions':''})
        result.append({'switch':DPID[server[0]],'name':'g2-p6-deny-return-'+client,'priority':'420','active':'true',
         'in_port':str(server[1]),'eth_type':'0x0800','ip_proto':'6','ipv4_src':server[3]+'/32',
         'ipv4_dst':ip+'/32','tcp_src':'443','actions':''})
    return result

def guards(): return old.guards()+notes_guards()

def permits(client,code,seconds):
    spec=SPEC[code]; target_host=spec['host']; result=[]
    for source,target in ((client,target_host),(target_host,client)):
        sw,port,mac,ip=HOSTS[source]; dst,dport,dmac,dip=HOSTS[target]; route=path(sw,dst)
        for k,switch in enumerate(route):
            incoming=port if k==0 else ADJ[switch][route[k-1]]
            outgoing=dport if k==len(route)-1 else ADJ[switch][route[k+1]]
            flow={'switch':DPID[switch],'name':spec['prefix']+'allow-'+source+'-'+target+'-'+switch,
             'priority':str(spec['allow_priority']),'active':'true','hard_timeout':str(seconds),'idle_timeout':'0',
             'in_port':str(incoming),'eth_src':mac,'eth_dst':dmac,'eth_type':'0x0800','ip_proto':'6',
             'ipv4_src':ip+'/32','ipv4_dst':dip+'/32','actions':'output='+str(outgoing)}
            flow['tcp_dst' if target==target_host else 'tcp_src']='443'; result.append(flow)
    return result

def owned_grant(name): return name.startswith(('g2-p5-allow-','g2-p6-allow-'))
def baseline(): return base_names()|{f['name'] for f in portal_flows()}|{f['name'] for f in guards()}

def bootstrap():
    deadline=time.monotonic()+55
    while not base_names().issubset(stored_names()):
        if time.monotonic()>deadline: raise RuntimeError('Step 2 not ready')
        time.sleep(1)
    for flow in guards(): push(flow)
    remove([f['name'] for f in old.old_flows()])
    remove([n for n in stored_names() if owned_grant(n)])
    for flow in portal_flows(): push(flow)
    verify()

def verify():
    until=time.monotonic()+3
    while not baseline().issubset(stored_names()):
        if time.monotonic()>until: raise RuntimeError('Base/portal/R1/R2 deny incomplete')
        time.sleep(.1)
    if any(f['name'] in stored_names() for f in old.old_flows()): raise RuntimeError('Fixed step3 permission still installed')
    print('STEP6_BASELINE_OK: 59 base + 8 portal + 4 R1 deny + 4 R2 deny = 75; grants per valid session',flush=True)

class Reconciler:
    def __init__(self): self.current={}
    def sync(self):
        present=stored_names()
        if not baseline().issubset(present): raise RuntimeError('Required baseline absent')
        if {s['switchDPID'] for s in api('/wm/core/controller/switches/json')}!=set(DPID.values()): raise RuntimeError('Switch missing')
        desired={}; effective={}; expected=set()
        with db() as conn,conn.cursor() as cur:
            cur.execute('''SELECT s.*,u.active,u.role_id AS current_role FROM sessions s JOIN users u ON u.id=s.user_id
             WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
             AND s.network_state IN ('pending','active','denied') ORDER BY s.created_at DESC''')
            for row in cur.fetchall():
                client=CLIENTS.get(row['terminal_ip'])
                if not client or client in desired: continue
                sw,port,mac,ip=HOSTS[client]
                if not row['active'] or row['role_id']!=row['current_role']: continue
                if (row['terminal_mac'],row['switch_dpid'],row['in_port'])!=(mac,DPID[sw],port): continue
                remaining=int((row['expires_at']-datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())
                desired[client]={'token':row['token_hash'],'role':row['current_role'],'seconds':max(0,min(LEASE,remaining))}
            cur.execute('''SELECT p.role_id,p.allowed,x.code,x.ip_address,x.port,x.transport,x.deployment_state
             FROM role_permissions p JOIN resources x ON x.id=p.resource_id WHERE x.code IN ('lms','notas')''')
            policies={(r['role_id'],r['code']):r for r in cur.fetchall()}
            for client in CLIENTS.values():
                item=desired.get(client); states={}
                for code,spec in SPEC.items():
                    policy=policies.get((item['role'],code)) if item else None
                    allowed=bool(item and item['seconds']>0 and policy and policy['allowed']
                     and policy['deployment_state']=='active' and policy['ip_address']==HOSTS[spec['host']][3]
                     and policy['port']==443 and policy['transport']=='TCP')
                    names={f['name'] for f in permits(client,code,LEASE)}; key=(client,code); prior=self.current.get(key)
                    signature=(item['token'] if item else None,allowed)
                    due=(prior is None or prior[:2]!=signature or time.monotonic()-prior[2]>=10
                     or (allowed and not names.issubset(present)) or (not allowed and bool(names & present)))
                    if due:
                        remove(names & present)
                        if allowed:
                            for flow in permits(client,code,item['seconds']): push(flow)
                        self.current[key]=(*signature,time.monotonic())
                    if allowed: expected.update(names)
                    states[code]='active' if allowed else 'denied'
                if item:
                    effective[client]=states
                    # Keep step5 identity semantics: network_state describes R1/LMS; R2 is reported per resource.
                    cur.execute('UPDATE sessions SET network_state=%s WHERE token_hash=%s AND revoked_at IS NULL',
                     (states['lms'],item['token']))
            cur.execute("UPDATE sessions SET network_state='revoked' WHERE network_state IN ('pending','active','denied') AND (revoked_at IS NOT NULL OR expires_at<=UTC_TIMESTAMP(6))")
        until=time.monotonic()+3
        while {n for n in stored_names() if owned_grant(n)}!=expected:
            if time.monotonic()>until: raise RuntimeError('Flow updates did not converge')
            time.sleep(.1)
        return {'ok':True,'terminals':{c:v['lms'] for c,v in effective.items()},'resources':effective}
    def fail_closed(self):
        self.current.clear()
        try: remove([n for n in stored_names() if owned_grant(n)])
        except Exception: pass

def daemon():
    old.Reconciler=Reconciler
    old.daemon()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=['bootstrap','verify','daemon'])
    globals()[parser.parse_args().action]()
