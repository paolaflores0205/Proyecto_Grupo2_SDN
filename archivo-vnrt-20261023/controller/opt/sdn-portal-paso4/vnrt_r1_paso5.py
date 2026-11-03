#!/usr/bin/env python3
"""R1 policy adapter: private UNIX socket, MySQL policy, scoped Floodlight flows."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import select
import socket
import sys
import time
sys.path.insert(0, '/opt/sdn-floodlight')
from vnrt_flujos_https_paso3 import api, DPID, HOSTS, ADJ, path, stored_names, base_names, flows as old_flows
from vnrt_flujos_portal_paso4 import flows as portal_flows
import pymysql

SOCKET='/run/sdn-r1/policy.sock'
CLIENTS={HOSTS[n][3]:n for n in ('h1','h2')}
LEASE=30

def db():
    CONFIG=json.loads(Path('/etc/sdn-portal-paso4/config.json').read_text())
    return pymysql.connect(host='127.0.0.1',user=CONFIG['db_user'],password=CONFIG['db_password'],
     database='sdn_g2',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,
     autocommit=True,connect_timeout=3,read_timeout=3,write_timeout=3)

def push(flow):
    result=api('/wm/staticflowpusher/json','POST',flow)
    if 'pushed' not in str(result).lower(): raise RuntimeError('Flow not accepted')

def remove(names):
    for name in names: api('/wm/staticflowpusher/json','DELETE',{'name':name})

def guards():
    result=[]
    for client in CLIENTS.values():
        sw,port,mac,ip=HOSTS[client]
        result.append({'switch':DPID[sw],'name':'g2-p5-deny-'+client,'priority':'400','active':'true',
         'in_port':str(port),'eth_type':'0x0800','ip_proto':'6','ipv4_dst':HOSTS['h3'][3]+'/32','tcp_dst':'443','actions':''})
        result.append({'switch':DPID['sw3'],'name':'g2-p5-deny-return-'+client,'priority':'400','active':'true',
         'in_port':str(HOSTS['h3'][1]),'eth_type':'0x0800','ip_proto':'6',
         'ipv4_src':HOSTS['h3'][3]+'/32','ipv4_dst':ip+'/32','tcp_src':'443','actions':''})
    return result

def permits(client,seconds):
    result=[]
    for source,target in ((client,'h3'),('h3',client)):
        sw,port,mac,ip=HOSTS[source]; dst,dport,dmac,dip=HOSTS[target]
        route=path(sw,dst)
        for k,switch in enumerate(route):
            incoming=port if k==0 else ADJ[switch][route[k-1]]
            outgoing=dport if k==len(route)-1 else ADJ[switch][route[k+1]]
            flow={'switch':DPID[switch],'name':'g2-p5-allow-'+source+'-'+target+'-'+switch,
             'priority':'450','active':'true','hard_timeout':str(seconds),'idle_timeout':'0',
             'in_port':str(incoming),'eth_src':mac,'eth_dst':dmac,'eth_type':'0x0800','ip_proto':'6',
             'ipv4_src':ip+'/32','ipv4_dst':dip+'/32','actions':'output='+str(outgoing)}
            flow['tcp_dst' if target=='h3' else 'tcp_src']='443'; result.append(flow)
    return result

def baseline():
    if not base_names().issubset(stored_names()): raise RuntimeError('Base connectivity missing')
    return base_names()|{f['name'] for f in portal_flows()}|{f['name'] for f in guards()}

def bootstrap():
    deadline=time.monotonic()+55
    while not base_names().issubset(stored_names()):
        if time.monotonic()>deadline: raise RuntimeError('Step 2 not ready')
        time.sleep(1)
    # Deny before removing the old fixed permission; never clear unrelated flows.
    for flow in guards(): push(flow)
    remove([f['name'] for f in old_flows()])
    remove([name for name in stored_names() if name.startswith('g2-p5-allow-')])
    for flow in portal_flows(): push(flow)
    verify()

def verify():
    current=stored_names()
    if not baseline().issubset(current): raise RuntimeError('Baseline/portal/deny missing')
    if any(f['name'] in current for f in old_flows()): raise RuntimeError('Old fixed permission still present')
    print('STEP5_BASELINE_OK: 59 base + 8 portal + 4 deny; fixed step3 rules absent',flush=True)

def sync_request():
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(15); conn.connect(SOCKET); conn.sendall(b'{"action":"sync"}\n')
        data=b''
        while b'\n' not in data:
            part=conn.recv(4096)
            if not part or len(data)>16384: raise RuntimeError('Invalid policy response')
            data+=part
    result=json.loads(data)
    if not result.get('ok'): raise RuntimeError('Policy adapter unavailable')
    return result

class Reconciler:
    def __init__(self): self.current={}
    def sync(self):
        present=stored_names()
        if not baseline().issubset(present): raise RuntimeError('Required deny or portal rules absent')
        live={s['switchDPID'] for s in api('/wm/core/controller/switches/json')}
        if live!=set(DPID.values()): raise RuntimeError('Switch missing')
        desired={}
        with db() as conn,conn.cursor() as cur:
            cur.execute('''SELECT s.*,u.active,u.role_id AS current_role,p.allowed,x.ip_address,x.port,x.deployment_state
             FROM sessions s JOIN users u ON u.id=s.user_id
             JOIN resources x ON x.code='lms' JOIN role_permissions p ON p.role_id=u.role_id AND p.resource_id=x.id
             WHERE s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP(6)
             AND s.network_state IN ('pending','active','denied') ORDER BY s.created_at DESC''')
            rows=cur.fetchall()
            for row in rows:
                client=CLIENTS.get(row['terminal_ip'])
                if not client or client in desired: continue
                sw,port,mac,ip=HOSTS[client]
                if not row['active'] or row['role_id']!=row['current_role']: continue
                if (row['terminal_mac'],row['switch_dpid'],row['in_port'])!=(mac,DPID[sw],port): continue
                allowed=bool(row['allowed']) and row['deployment_state']=='active' and row['ip_address']==HOSTS['h3'][3] and row['port']==443
                remaining=int((row['expires_at']-datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())
                desired[client]=(row['token_hash'],allowed,max(0,min(LEASE,remaining)))
            for client in CLIENTS.values():
                item=desired.get(client); old=self.current.get(client)
                names={f['name'] for f in permits(client,LEASE)}
                allowed=bool(item and item[1] and item[2]>0)
                due=old is None or old[0]!=(item[0] if item else None) or old[1]!=allowed or time.monotonic()-old[2]>=10 or not names.issubset(present)
                if due:
                    # DELETE then ADD resets hard_timeout in OVS; deny guards cover the short renewal interval.
                    remove(names & present)
                    if allowed:
                        for flow in permits(client,item[2]): push(flow)
                    self.current[client]=(item[0] if item else None,allowed,time.monotonic())
                if item:
                    cur.execute('UPDATE sessions SET network_state=%s WHERE token_hash=%s AND revoked_at IS NULL',
                     ('active' if allowed else 'denied',item[0]))
            cur.execute("UPDATE sessions SET network_state='revoked' WHERE network_state IN ('pending','active','denied') AND (revoked_at IS NOT NULL OR expires_at<=UTC_TIMESTAMP(6))")
        expected={f['name'] for client,item in desired.items() if item[1] and item[2]>0 for f in permits(client,item[2])}
        until=time.monotonic()+3
        while True:
            actual={n for n in stored_names() if n.startswith('g2-p5-allow-')}
            if actual==expected: break
            if time.monotonic()>until: raise RuntimeError('Flow updates did not converge')
            time.sleep(.1)
        return {'ok':True,'terminals':{client:('active' if value[1] and value[2]>0 else 'denied') for client,value in desired.items()}}
    def fail_closed(self):
        self.current.clear()
        try: remove([n for n in stored_names() if n.startswith('g2-p5-allow-')])
        except Exception: pass  # Unreachable controller: switch hard_timeout bounds the remaining permission.

def daemon():
    reconciler=Reconciler()
    # Recreate only this service's known socket, inside systemd's dedicated RuntimeDirectory.
    if os.path.exists(SOCKET):
        import stat
        if not stat.S_ISSOCK(os.stat(SOCKET).st_mode): raise RuntimeError('Unexpected runtime file')
        os.unlink(SOCKET)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(SOCKET); os.chmod(SOCKET,0o600); server.listen(8)
        while True:
            ready,_,_=select.select([server],[],[],2)
            conn=None
            try:
                if ready:
                    conn,_=server.accept(); conn.settimeout(2)
                    raw=conn.recv(4096)
                    if raw!=b'{"action":"sync"}\n': raise RuntimeError('Invalid local request')
                result=reconciler.sync()
            except Exception as error:
                reconciler.fail_closed(); result={'ok':False}
                print('R1 denied: '+type(error).__name__,flush=True)
            if conn:
                try: conn.sendall((json.dumps(result)+'\n').encode())
                except OSError: pass
                finally: conn.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=['bootstrap','verify','daemon','sync'])
    action=parser.parse_args().action
    if action=='sync': print(json.dumps(sync_request()))
    else: globals()[action]()
