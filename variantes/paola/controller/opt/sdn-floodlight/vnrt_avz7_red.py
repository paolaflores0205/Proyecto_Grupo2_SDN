"""Final R1/R2 flow design, with configurable addresses and OVS port numbers."""
import argparse,json,time
from vnrt_flujos_https_paso3 import C,DPID,HOSTS,ADJ,path,stored_names,api
P='g2-v7-'
SPEC={'lms':('h3',443),'notas':('h4',443),'administracion':('h4',8443)}
CLIENTS={HOSTS[n][3]:n for n in ('h1','h2')}
def flow(sw,name,priority,actions='',table=0,**match):
    return dict(switch=DPID[sw],name=P+name,table=str(table),priority=str(priority),active='true',
        idle_timeout='0',hard_timeout='0',actions=actions,**{k:str(v) for k,v in match.items()})

def context(client):
    return '0x1' if client=='h1' else '0x2'
def baseline():
    result=[]
    for sw in DPID:
        result.append(flow(sw,'default-'+sw,50))
        if sw=='sw2':
            for table in (10,20,30):
                result.append(flow(sw,f'default-{sw}-table-{table}',50,table=table))
        for port in ADJ[sw].values():
            for typ in ('0x88cc','0x8942'):
                result.append(flow(sw,'discovery-'+sw+'-'+str(port)+'-'+typ,64000,
                    'output=controller',in_port=port,eth_type=typ))
    for name,(origin,port,mac,ip) in HOSTS.items():
        for sw in DPID:
            if name in ('h1','h2') and sw!='sw2':continue
            route=path(origin,sw);incoming=port if len(route)==1 else ADJ[sw][route[-2]]
            outputs=[int(p) for p in C['switches'][sw]['ports'] if int(p)!=incoming]
            actions=','.join('output='+str(p) for p in outputs)
            if sw==origin and name in ('h1','h2'):actions+=',output=controller'
            result.append(flow(sw,'arp-'+name+'-'+sw,300,actions,in_port=incoming,eth_src=mac,eth_type='0x0806'))
    cport=HOSTS['controller'][1];a=ADJ['sw1']['sw2'];s=ADJ['sw1']['sw3']
    up=ADJ['sw2']['sw1'];sup=ADJ['sw3']['sw1']
    h3p=HOSTS['h3'][1];h4p=HOSTS['h4'][1]
    result.append(flow('sw1','arp-access-transit-sw1',300,f'output={cport},output={s}',in_port=a,eth_type='0x0806'))
    result.append(flow('sw3','arp-access-transit-sw3',300,f'output={h4p},output={h3p}',in_port=sup,eth_type='0x0806'))
    for client in CLIENTS.values():
        sw,port,mac,ip=HOSTS[client]
        result.append(flow(sw,'dhcp-'+client+'-'+sw,400,'output='+str(up),
            in_port=port,eth_src=mac,eth_type='0x0800',ip_proto=17,udp_src=68,udp_dst=67))
        for source,target in ((client,'controller'),('controller',client)):
            origin,inp,smac,sip=HOSTS[source];end,out,dmac,dip=HOSTS[target];route=path(origin,end)
            for i,switch in enumerate(route):
                if switch=='sw1':continue
                incoming=inp if i==0 else ADJ[switch][route[i-1]]
                outgoing=out if i==len(route)-1 else ADJ[switch][route[i+1]]
                fields=dict(in_port=incoming,eth_src=smac,eth_dst=dmac,eth_type='0x0800',
                    ip_proto=6,ipv4_src=sip+'/32',ipv4_dst=dip+'/32')
                fields['tcp_dst' if target=='controller' else 'tcp_src']=443
                result.append(flow(switch,'portal-'+source+'-'+target+'-'+switch,400,'output='+str(outgoing),**fields))
    _,_,servermac,serverip=HOSTS['controller']
    for sw,inp,actions in [('sw1',cport,'output='+str(a)),('sw2',up,'output='+str(HOSTS['h1'][1])+',output='+str(HOSTS['h2'][1]))]:
        result.append(flow(sw,'dhcp-return-'+sw,400,actions,in_port=inp,eth_src=servermac,
            eth_type='0x0800',ipv4_src=serverip+'/32',ip_proto=17,udp_src=67,udp_dst=68))
    result.append(flow('sw1','dhcp-access-transit',400,'output='+str(cport),in_port=a,
        eth_type='0x0800',ip_proto=17,udp_src=68,udp_dst=67))
    result.append(flow('sw1','portal-access-transit',400,'output='+str(cport),in_port=a,eth_dst=servermac,
        eth_type='0x0800',ipv4_src=C['data_cidr'],ipv4_dst=serverip+'/32',ip_proto=6,tcp_dst=443))
    result.append(flow('sw1','portal-return-transit',400,'output='+str(a),in_port=cport,eth_src=servermac,
        eth_type='0x0800',ipv4_src=serverip+'/32',ipv4_dst=C['data_cidr'],ip_proto=6,tcp_src=443))
    for code,(server,port) in SPEC.items():
        _,_,mac,ip=HOSTS[server]
        result.append(flow('sw1','transit-'+code+'-ida',350,'output='+str(s),in_port=a,
            eth_dst=mac,eth_type='0x0800',ipv4_src=C['data_cidr'],ipv4_dst=ip+'/32',ip_proto=6,tcp_dst=port))
        result.append(flow('sw1','transit-'+code+'-retorno',350,'output='+str(a),in_port=s,
            eth_src=mac,eth_type='0x0800',ipv4_src=ip+'/32',ipv4_dst=C['data_cidr'],ip_proto=6,tcp_src=port))
    # Table 0 keeps unauthenticated portal/DHCP/ARP exceptions. Other TCP
    # candidates enter the identity pipeline but cannot leave without a session.
    for client in ('h1','h2'):
        _,port,mac,ip=HOSTS[client];meta=context(client)
        result.append(flow('sw2','candidate-'+client+'-ida',100,table=0,
            instruction_goto_table=10,in_port=port,eth_src=mac,eth_type='0x0800',
            ip_proto=6,ipv4_src=ip+'/32'))
        result.append(flow('sw2','candidate-'+client+'-retorno',100,table=0,
            instruction_goto_table=10,in_port=up,eth_dst=mac,eth_type='0x0800',
            ip_proto=6,ipv4_dst=ip+'/32'))
        result.append(flow('sw2','forward-'+client+'-ida',300,'output='+str(up),table=30,
            metadata=meta,in_port=port,eth_src=mac,eth_type='0x0800',ipv4_src=ip+'/32'))
        result.append(flow('sw2','forward-'+client+'-retorno',300,'output='+str(port),table=30,
            metadata=meta,in_port=up,eth_dst=mac,eth_type='0x0800',ipv4_dst=ip+'/32'))
    return result

def session_rules(client,seconds,session_id):
    _,port,mac,ip=HOSTS[client];up=ADJ['sw2']['sw1'];meta=context(client)
    suffix=session_id[:16]+'-'+client
    result=[]
    for direction,inp,fields in (
        ('ida',port,dict(eth_src=mac,ipv4_src=ip+'/32')),
        ('retorno',up,dict(eth_dst=mac,ipv4_dst=ip+'/32'))):
        # Only the two client-context bits are used; Floodlight 1.2 parses
        # the metadata mask as a signed Java long.
        f=flow('sw2','identity-'+suffix+'-'+direction,700,table=10,
            instruction_write_metadata=meta+'/0x3',
            instruction_goto_table=20,in_port=inp,eth_type='0x0800',ip_proto=6,**fields)
        f['hard_timeout']=str(seconds);result.append(f)
    return result
def permissions(client,code,seconds,session_id):
    server,service=SPEC[code];sw,port,mac,ip=HOSTS[client];_,sport,smac,sip=HOSTS[server]
    suffix=session_id[:16]+'-'+client+'-'+code;result=[]
    for switch,name,inp,out,srcmac,dstmac,srcip,dstip,field in [
        ('sw2','ida',port,ADJ['sw2']['sw1'],mac,smac,ip,sip,'tcp_dst'),
        ('sw3','ida',ADJ['sw3']['sw1'],sport,mac,smac,ip,sip,'tcp_dst'),
        ('sw3','retorno',sport,ADJ['sw3']['sw1'],smac,mac,sip,ip,'tcp_src'),
        ('sw2','retorno',ADJ['sw2']['sw1'],port,smac,mac,sip,ip,'tcp_src')]:
        f=flow(switch,'grant-'+suffix+'-'+switch+'-'+name,800,
            'output='+str(out) if switch=='sw3' else '',table=20 if switch=='sw2' else 0,
            in_port=inp,eth_src=srcmac,eth_dst=dstmac,eth_type='0x0800',
            ipv4_src=srcip+'/32',ipv4_dst=dstip+'/32',ip_proto=6,
            **({'metadata':context(client),'instruction_goto_table':30} if switch=='sw2' else {}),
            **{field:service})
        f['hard_timeout']=str(seconds);result.append(f)
    return result

def push(f):
    r = api('/wm/staticflowpusher/json', 'POST', f)
    if 'pushed' not in str(r).lower():
        raise RuntimeError('Controller rejected flow')

def remove(names):
    for name in names:
        api('/wm/staticflowpusher/json', 'DELETE', {'name': name})

def all_actual():
    result = {}
    for sw, dpid in DPID.items():
        raw = api('/wm/core/switch/' + dpid + '/flow/json')
        rows = []

        def visit(value):
            if isinstance(value, dict):
                if 'match' in value and 'priority' in value:
                    rows.append(value)
                else:
                    for item in value.values():
                        visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        visit(raw)
        result[dpid] = rows
    return result

def normal(key, value):
    if isinstance(value, dict):
        value = value.get('portNumber', value.get('value', value))
    text = str(value).lower()
    while text.startswith('0x0x'):
        text = text[2:]
    if key in ('eth_type', 'ip_proto', 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst', 'in_port', 'metadata'):
        try:
            head=text.split('/')[0]
            return int(head, 16) if head.startswith('0x') else int(head)
        except ValueError:
            return text
    if key.startswith('ipv4_'):
        import ipaddress
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return text
    return text

def actual_contains(f, rows):
    keys = ('in_port', 'eth_src', 'eth_dst', 'eth_type', 'ip_proto', 'ipv4_src', 'ipv4_dst', 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst', 'metadata')
    for r in rows:
        if normal('in_port', r['priority']) != int(f['priority']):
            continue
        if normal('in_port', r.get('tableId', r.get('table_id', 0))) != int(f['table']):
            continue
        match = r['match']
        if set(match) != {k for k in keys if k in f}:
            continue
        if all((k in match and normal(k, match[k]) == normal(k, f[k]) for k in keys if k in f)):
            instructions=r.get('instructions', {})
            if isinstance(instructions,dict):
                actual=instructions.get('instruction_apply_actions', {}).get('actions', '')
            else:
                actual=''
            if sorted(str(actual).lower().split(',')) != sorted(f['actions'].lower().split(',')) and (not (not f['actions'] and (not actual))):
                continue
            # A nonzero-table rule is effective only if OVS has the expected
            # continuation instruction, not merely a matching entry.
            detail=json.dumps(instructions,sort_keys=True).lower()
            if 'instruction_goto_table' in f:
                if 'goto' not in detail or str(f['instruction_goto_table']) not in detail:
                    continue
            if 'instruction_write_metadata' in f:
                if 'metadata' not in detail or str(normal('metadata',f['instruction_write_metadata'])) not in detail:
                    continue
            timeout = normal('in_port', r.get('hardTimeoutSec', 0))
            if f['name'].startswith(P + 'grant-') and (not (isinstance(timeout, int) and 0 < timeout <= 30)):
                continue
            return True
    return False

def verify_actual(wanted, timeout=4):
    until = time.monotonic() + timeout
    while True:
        observed = all_actual()
        missing = [f['name'] for f in wanted if not actual_contains(f, observed[f['switch']])]
        if not missing:
            return observed
        if time.monotonic() > until:
            raise RuntimeError('Actual OVS rules missing: ' + ','.join(missing[:6]))
        time.sleep(0.2)

def bootstrap():
    until = time.monotonic() + 55
    while True:
        try:
            if {s['switchDPID'] for s in api('/wm/core/controller/switches/json')} == set(DPID.values()):
                break
        except Exception:
            pass
        if time.monotonic() > until:
            raise RuntimeError('Switches unavailable')
        time.sleep(1)
    wanted = baseline()
    defaults = {f['name'] for f in wanted if f['name'].startswith(P + 'default-')}
    remove([n for n in stored_names() if n in defaults])
    for f in wanted:
        if f['name'] in defaults:
            push(f)
    verify_actual([f for f in wanted if f['name'] in defaults], timeout=15)
    remove([n for n in stored_names() if n.startswith(('g2-p2-', 'g2-p3-', 'g2-p4-', 'g2-p5-', 'g2-p6-')) or (n.startswith(P) and n not in defaults)])
    for f in wanted:
        if f['name'] not in defaults:
            push(f)
    verify_actual(wanted, timeout=15)
    print(json.dumps({'baseline': len(wanted), 'individual_per_permission': 4,
                      'identity_rules_per_session': 2, 'metadata': True}))

if __name__=="__main__":
 p=argparse.ArgumentParser();p.add_argument("action",choices=["bootstrap","show","verify"]);a=p.parse_args().action
 if a=="show":print(json.dumps(baseline(),indent=2))
 elif a=="verify":verify_actual(baseline());print("OVS_BASELINE_VERIFIED")
 else:bootstrap()
