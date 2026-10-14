"""Offline generation only. No SSH, network writes or credential reuse."""
import argparse,ast,hashlib,ipaddress,json,re,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def validate(c,allow_example=False):
    assert c['confirmed_after_inventory'] is True or allow_example,'Confirm inventory first'
    assert set(c['nodes'])=={'controller','h1','h2','h3','h4'}
    assert set(c['switches'])=={'sw1','sw2','sw3'}
    subnet=ipaddress.ip_network(c['data_cidr'],strict=True);assert subnet.version==4
    control=ipaddress.ip_address(c['controller_management_ip']);assert control not in subnet
    ips=set();macs=set();dpids=set()
    roles={'controller':'sw1','h1':'sw2','h2':'sw2','h3':'sw3','h4':'sw3'}
    occupied={n:set(s['links'].values()) for n,s in c['switches'].items()}
    for n,s in c['nodes'].items():
        ip=ipaddress.ip_address(s['ip']);assert ip in subnet and ip not in (subnet.network_address,subnet.broadcast_address)
        assert str(ip) not in ips;ips.add(str(ip))
        assert re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',s['mac']) and not (int(s['mac'][:2],16)&1)
        assert s['mac'] not in macs;macs.add(s['mac'])
        assert s['switch']==roles[n] and isinstance(s['port'],int) and 0<s['port']<65280
        assert str(s['port']) in c['switches'][s['switch']]['ports']
        assert s['port'] not in occupied[s['switch']];occupied[s['switch']].add(s['port'])
        for key in ('management_interface','data_interface'):assert re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',s[key])
        assert s['management_interface']!=s['data_interface']
    expected={'sw1':{'sw2','sw3'},'sw2':{'sw1'},'sw3':{'sw1'}}
    for n,s in c['switches'].items():
        assert set(s['links'])==expected[n]
        assert len(set(s['links'].values()))==len(s['links'])
        assert re.fullmatch(r'(?:[0-9a-f]{2}:){7}[0-9a-f]{2}',s['dpid']) and s['dpid'] not in dpids;dpids.add(s['dpid'])
        assert re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',s['bridge'])
        assert set(map(int,s['ports']))==occupied[n], 'Unspecified extra switch port: review topology'
        assert len(set(s['ports'].values()))==len(s['ports'])
        for p,iface in s['ports'].items():
            assert p==str(int(p)) and 0<int(p)<65280
            assert re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',iface) and iface!=s['management_interface']
    assert not any(k.lower() in {'password','db_password','secret_key'} for k in c['ssh'])
    assert set(c['ssh']['ports'])==set(c['nodes'])|set(c['switches'])
    for p in c['ssh']['ports'].values():assert isinstance(p,int) and 0<p<=65535
    return c
def render(config,output,allow_example=False):
    c=validate(json.loads(Path(config).read_text(encoding='utf8')),allow_example)
    out=Path(output).resolve();assert not out.exists(),'Output already exists; use a new directory'
    out.mkdir(parents=True)
    shutil.copytree(ROOT/'source',out/'source')
    for name in ('schema.sql','install_node.py','network_data.py','seed_database.py','smoke_test.py'):
        shutil.copy2(ROOT/name,out/name)
    shutil.copytree(ROOT/'vendor',out/'vendor')
    (out/'topology.json').write_text(json.dumps(c,indent=2),encoding='utf8')
    context=(out/'source/portable_context.py').read_text(encoding='utf8')
    (out/'source/vnrt_flujos_https_paso3.py').write_text(context,encoding='utf8')
    flows=(out/'source/portable_flows.py').read_text(encoding='utf8')+'\n'+(out/'source/verified_flow_helpers.py.inc').read_text(encoding='utf8')
    flows+='\nif __name__=="__main__":\n p=argparse.ArgumentParser();p.add_argument("action",choices=["bootstrap","show","verify"]);a=p.parse_args().action\n if a=="show":print(json.dumps(baseline(),indent=2))\n elif a=="verify":verify_actual(baseline());print("OVS_BASELINE_VERIFIED")\n else:bootstrap()\n'
    (out/'source/vnrt_avz7_red.py').write_text(flows,encoding='utf8')
    replacements={'192.0.2.10':c['nodes']['controller']['ip'],'192.0.2.101':c['nodes']['h3']['ip'],
        '192.0.2.102':c['nodes']['h4']['ip'],'198.51.100.10':c['controller_management_ip']}
    for p in (out/'source').rglob('*'):
        if p.is_file() and p.suffix in ('.py','.html','.properties'):
            text=p.read_text(encoding='utf8')
            for i,key in enumerate(replacements):text=text.replace(key,f'__SDN_ADDRESS_{i}__')
            for i,value in enumerate(replacements.values()):text=text.replace(f'__SDN_ADDRESS_{i}__',value)
            if p.suffix=='.py':ast.parse(text)
            p.write_text(text,encoding='utf8',newline='\n')
    import os,importlib.util
    os.environ['SDN_TOPOLOGY']=str(out/'topology.json');sys.path.insert(0,str(out/'source'))
    spec=importlib.util.spec_from_file_location('offline_flows',out/'source/vnrt_avz7_red.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    catalog=module.baseline();assert len(catalog)==41
    (out/'catalog_base.json').write_text(json.dumps(catalog,indent=2),encoding='utf8')
    individual=[f for h in ('h1','h2') for resource in module.SPEC for f in module.permissions(h,resource,30,'OFFLINE_EXAMPLE_NOT_A_SESSION')]
    (out/'catalog_examples.json').write_text(json.dumps(individual,indent=2),encoding='utf8')
    print('Generated files only; no VM changed. Baseline: 41. Permissions: 4 per session-resource.')
    return out
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('config');p.add_argument('--out',required=True);a=p.parse_args()
    render(a.config,a.out)
