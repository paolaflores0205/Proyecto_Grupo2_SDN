#!/usr/bin/env python3
"""Pre-login access to portal only; login/logout never invokes this script."""
import argparse
from pathlib import Path
import sys
import time
sys.path.insert(0,'/opt/sdn-floodlight')
from vnrt_flujos_https_paso3 import api, DPID, HOSTS, ADJ, path, stored_names, base_names, flows as step3_flows

def flows():
    result=[]
    for client in ('h1','h2'):
        for source,target in ((client,'controller'),('controller',client)):
            sw,port,mac,ip=HOSTS[source]; dst,dport,dmac,dip=HOSTS[target]
            route=path(sw,dst)
            for k,switch in enumerate(route):
                incoming=port if k==0 else ADJ[switch][route[k-1]]
                outgoing=dport if k==len(route)-1 else ADJ[switch][route[k+1]]
                flow={'switch':DPID[switch],'name':'g2-p4-portal-'+source+'-'+target+'-'+switch,'priority':'310','active':'true','in_port':str(incoming),'eth_src':mac,'eth_dst':dmac,'eth_type':'0x0800','ip_proto':'6','ipv4_src':ip+'/32','ipv4_dst':dip+'/32','actions':'output='+str(outgoing)}
                flow['tcp_dst' if target=='controller' else 'tcp_src']='443'
                result.append(flow)
    return result

def main(action):
    wanted=flows(); names={flow['name'] for flow in wanted}
    if action=='show':
        import json
        print(json.dumps(wanted,indent=2)); return
    prerequisites=base_names()|{f['name'] for f in step3_flows()}
    if action=='apply':
        deadline=time.monotonic()+55
        while not prerequisites.issubset(stored_names()):
            if time.monotonic()>deadline: raise RuntimeError('Previous steps are not ready')
            time.sleep(1)
        for flow in wanted:
            reply=api('/wm/staticflowpusher/json','POST',flow)
            if 'pushed' not in str(reply).lower(): raise RuntimeError(str(reply))
    elif action=='remove':
        for name in names: api('/wm/staticflowpusher/json','DELETE',{'name':name})
    for _ in range(15):
        current=stored_names()
        ready=not names.intersection(current) if action=='remove' else names.issubset(current)
        if ready: break
        time.sleep(.3)
    else: raise RuntimeError('Portal flow change did not converge')
    if not prerequisites.issubset(current): raise RuntimeError('Previous rules are incomplete')
    print('STEP4_'+action.upper()+'_OK',len(wanted),'pre-login portal rules; previous66 preserved')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=['show','apply','verify','remove'])
    main(parser.parse_args().action)
