#!/usr/bin/env python3
"""Install only known-host ARP and ICMP through Floodlight's LOCAL REST API."""
import argparse
import collections
import json
import time
import urllib.request

URL='http://127.0.0.1:8080'
DPID={'sw1':'00:00:00:00:36:d8:d8:e5','sw2':'00:00:00:00:0f:a7:1a:79','sw3':'00:00:00:00:36:d3:f6:2a'}
HOSTS={'controller':('sw1',1,'02:00:f2:37:54:6c','192.0.2.10'),
 'h1':('sw2',2,'02:00:ba:90:ba:89','192.0.2.1'),
 'h2':('sw2',3,'02:00:6a:da:81:26','192.0.2.2'),
 'h3':('sw3',2,'02:00:ec:98:49:d9','192.0.2.101'),
 'h4':('sw3',1,'02:00:dd:20:da:b9','192.0.2.102')}
ADJ={'sw1':{'sw2':2,'sw3':3},'sw2':{'sw1':1},'sw3':{'sw1':3}}
def api(path,method='GET',data=None):
 req=urllib.request.Request(URL+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
 with urllib.request.urlopen(req,timeout=4) as r: return json.load(r)
def path(src,dst):
 q=collections.deque([(src,[src])]); seen=set()
 while q:
  n,p=q.popleft()
  if n==dst: return p
  if n in seen: continue
  seen.add(n)
  for v in ADJ[n]: q.append((v,p+[v]))
 raise RuntimeError('No path')
def flows():
 out=[]
 for name,(src,port,mac,ip) in HOSTS.items():
  for sw in DPID:
   p=path(src,sw); incoming=port if len(p)==1 else ADJ[sw][p[-2]]
   destinations=[i for i in [1,2,3] if i!=incoming]
   out.append({'switch':DPID[sw],'name':'g2-p2-arp-'+name+'-'+sw,'priority':'100','active':'true','in_port':str(incoming),'eth_src':mac,'eth_type':'0x0806','actions':','.join('output='+str(i) for i in destinations)})
  for target,(dst,dport,dmac,dip) in HOSTS.items():
   if target==name: continue
   p=path(src,dst)
   for k,sw in enumerate(p):
    incoming=port if k==0 else ADJ[sw][p[k-1]]
    outgoing=dport if k==len(p)-1 else ADJ[sw][p[k+1]]
    out.append({'switch':DPID[sw],'name':'g2-p2-icmp-'+name+'-'+target+'-'+sw,'priority':'200','active':'true','in_port':str(incoming),'eth_src':mac,'eth_dst':dmac,'eth_type':'0x0800','ip_proto':'1','ipv4_src':ip+'/32','ipv4_dst':dip+'/32','actions':'output='+str(outgoing)})
 return out
def main(action):
 if action=='show': print(json.dumps(flows(),indent=2)); return
 until=time.monotonic()+55
 ready=0
 while True:
  try:
   switches=api('/wm/core/controller/switches/json')
   if action=='apply':
    direct=api('/wm/topology/links/json')
    external=api('/wm/topology/external-links/json')
    def edge(row):
     return tuple(sorted(((row['src-switch'],int(row['src-port'])),(row['dst-switch'],int(row['dst-port'])))))
    found={edge(r) for r in direct+external}
    expected={tuple(sorted(((DPID['sw1'],2),(DPID['sw2'],1)))),tuple(sorted(((DPID['sw1'],3),(DPID['sw3'],3))))}
    all_ready={s['switchDPID'] for s in switches}==set(DPID.values()) and expected.issubset(found)
    ready=ready+1 if all_ready else 0
    if ready<3:
     if time.monotonic()>until: raise TimeoutError('The three switches and expected links are not ready.')
     time.sleep(1); continue
   break
  except Exception:
   if time.monotonic()>until: raise
   time.sleep(1)
 if action=='apply':
  for flow in flows():
   result=api('/wm/staticflowpusher/json','POST',flow)
   if 'pushed' not in str(result).lower(): raise RuntimeError(str(result))
  # REST accepts entries asynchronously; confirm names after processing.
  for attempt in range(10):
   text=json.dumps(api('/wm/staticflowpusher/list/all/json'))
   if all(f['name'] in text for f in flows()): break
   time.sleep(.5)
  else: raise RuntimeError('REST accepted flows but the complete baseline was not stored.')
  print('BASELINE_PUSHED',len(flows()),flush=True)
 elif action=='verify':
  stored=api('/wm/staticflowpusher/list/all/json')
  text=json.dumps(stored)
  missing=[f['name'] for f in flows() if f['name'] not in text]
  if missing: raise SystemExit('Missing baseline: '+str(missing))
  print('BASELINE_STORED_OK',len(flows()))
  print(json.dumps(api('/wm/core/controller/switches/json'),indent=2))
  print(json.dumps(api('/wm/topology/links/json'),indent=2))
  print(json.dumps(api('/wm/topology/external-links/json'),indent=2))
 elif action=='remove':
  for flow in flows(): api('/wm/staticflowpusher/json','DELETE',{'name':flow['name']})
  api('/wm/staticflowpusher/json','DELETE',{'name':'g2-p2-prueba-drop-h1-h3'})
  for attempt in range(10):
   text=json.dumps(api('/wm/staticflowpusher/list/all/json'))
   if not any(f['name'] in text for f in flows()) and 'g2-p2-prueba-drop-h1-h3' not in text: break
   time.sleep(.5)
  else: raise RuntimeError('Baseline removal has not completed; do not stop the controller yet.')
  print('BASELINE_REMOVED')
 elif action=='block-test':
  flow={'switch':DPID['sw2'],'name':'g2-p2-prueba-drop-h1-h3','priority':'450','active':'true','in_port':'2','eth_src':HOSTS['h1'][2],'eth_dst':HOSTS['h3'][2],'eth_type':'0x0800','ip_proto':'1','ipv4_src':HOSTS['h1'][3]+'/32','ipv4_dst':HOSTS['h3'][3]+'/32','actions':''}
  print(api('/wm/staticflowpusher/json','POST',flow))
 elif action=='unblock-test': print(api('/wm/staticflowpusher/json','DELETE',{'name':'g2-p2-prueba-drop-h1-h3'}))
parser=argparse.ArgumentParser()
parser.add_argument('action',choices=['show','apply','verify','remove','block-test','unblock-test'])
main(parser.parse_args().action)
