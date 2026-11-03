#!/usr/bin/env python3
"""Scoped fixed HTTPS test permission; not dynamic authentication/RBAC."""
import argparse
import json
import collections
import time
import urllib.request

DPID={'sw1':'00:00:00:00:36:d8:d8:e5','sw2':'00:00:00:00:0f:a7:1a:79','sw3':'00:00:00:00:36:d3:f6:2a'}
HOSTS={'controller':('sw1',1,'02:00:f2:37:54:6c','192.0.2.10'),
 'h1':('sw2',2,'02:00:ba:90:ba:89','192.0.2.1'),
 'h2':('sw2',3,'02:00:6a:da:81:26','192.0.2.2'),
 'h3':('sw3',2,'02:00:ec:98:49:d9','192.0.2.101'),
 'h4':('sw3',1,'02:00:dd:20:da:b9','192.0.2.102')}
ADJ={'sw1':{'sw2':2,'sw3':3},'sw2':{'sw1':1},'sw3':{'sw1':3}}

def api(path,method='GET',data=None):
    request=urllib.request.Request('http://127.0.0.1:8080'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
    with urllib.request.urlopen(request,timeout=5) as r: return json.load(r)

def path(src,dst):
    queue=collections.deque([(src,[src])]); visited=set()
    while queue:
        node,route=queue.popleft()
        if node==dst: return route
        if node in visited: continue
        visited.add(node)
        for neighbor in ADJ[node]: queue.append((neighbor,route+[neighbor]))
    raise RuntimeError('No path')

def base_names():
    names={'g2-p2-arp-'+host+'-'+sw for host in HOSTS for sw in DPID}
    for source,(src,*_) in HOSTS.items():
        for target,(dst,*_) in HOSTS.items():
            if source!=target:
                names.update('g2-p2-icmp-'+source+'-'+target+'-'+sw for sw in path(src,dst))
    return names

def flows():
    out=[]
    for source,target in [('h1','h3'),('h3','h1')]:
        sw,port,mac,ip=HOSTS[source]
        dst,dport,dmac,dip=HOSTS[target]
        route=path(sw,dst)
        for k,switch in enumerate(route):
            incoming=port if k==0 else ADJ[switch][route[k-1]]
            outgoing=dport if k==len(route)-1 else ADJ[switch][route[k+1]]
            f={'switch':DPID[switch],'name':'g2-p3-https-'+source+'-'+target+'-'+switch,'priority':'300','active':'true','in_port':str(incoming),'eth_src':mac,'eth_dst':dmac,'eth_type':'0x0800','ip_proto':'6','ipv4_src':ip+'/32','ipv4_dst':dip+'/32','actions':'output='+str(outgoing)}
            f['tcp_dst' if target=='h3' else 'tcp_src']='443'
            out.append(f)
    out.append({'switch':DPID['sw2'],'name':'g2-p3-deny-h2-h3-sw2','priority':'350','active':'true','in_port':'3','eth_src':HOSTS['h2'][2],'eth_dst':HOSTS['h3'][2],'eth_type':'0x0800','ip_proto':'6','ipv4_src':HOSTS['h2'][3]+'/32','ipv4_dst':HOSTS['h3'][3]+'/32','tcp_dst':'443','actions':''})
    return out

def stored_names():
    data=api('/wm/staticflowpusher/list/all/json')
    names=set()
    for entries in data.values():
        if isinstance(entries,list):
            for entry in entries: names.update(entry)
        elif isinstance(entries,dict): names.update(entries)
    return names

def main(action):
    desired=flows(); names={f['name'] for f in desired}
    if action=='show':
        print(json.dumps(desired,indent=2)); return
    if action=='apply':
        end=time.monotonic()+55
        while True:
            try:
                present={r['switchDPID'] for r in api('/wm/core/controller/switches/json')}
                ready=present==set(DPID.values()) and base_names().issubset(stored_names())
                if ready: break
            except Exception: pass
            if time.monotonic()>end: raise RuntimeError('Step 2 is not ready')
            time.sleep(1)
        for flow in desired:
            result=api('/wm/staticflowpusher/json','POST',flow)
            if 'pushed' not in str(result).lower(): raise RuntimeError(str(result))
    elif action=='remove':
        for name in names: api('/wm/staticflowpusher/json','DELETE',{'name':name})
    for _ in range(15):
        current=stored_names()
        ok=not names.intersection(current) if action=='remove' else names.issubset(current)
        if ok: break
        time.sleep(.3)
    else: raise RuntimeError('Flow change did not converge')
    if not base_names().issubset(current):
        raise RuntimeError('Step 2 baseline is incomplete')
    print('STEP3_'+action.upper()+'_OK',len(desired),'rules; baseline59 preserved',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=['show','apply','verify','remove'])
    main(parser.parse_args().action)
