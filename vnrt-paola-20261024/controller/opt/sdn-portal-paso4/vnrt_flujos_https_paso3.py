"""Compatibility names, now loaded from inventory instead of Matthew's network."""
import collections,json,os,urllib.request
from pathlib import Path
C=json.loads(Path(os.environ.get('SDN_TOPOLOGY','/etc/sdn-g2/topology.json')).read_text())
DPID={n:s['dpid'] for n,s in C['switches'].items()}
ADJ={n:s['links'] for n,s in C['switches'].items()}
HOSTS={n:(s['switch'],s['port'],s['mac'],s['ip']) for n,s in C['nodes'].items()}
def api(path,method='GET',data=None):
    req=urllib.request.Request('http://127.0.0.1:8080'+path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'Content-Type':'application/json'},method=method)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=5) as response:return json.load(response)
def path(src,dst):
    queue=collections.deque([(src,[src])]);seen=set()
    while queue:
        node,route=queue.popleft()
        if node==dst:return route
        if node in seen:continue
        seen.add(node)
        queue.extend((n,route+[n]) for n in ADJ[node])
    raise RuntimeError('No path')
def stored_names():
    result=set()
    for entries in api('/wm/staticflowpusher/list/all/json').values():
        if isinstance(entries,list):
            for entry in entries:result.update(entry)
        elif isinstance(entries,dict):result.update(entries)
    return result
