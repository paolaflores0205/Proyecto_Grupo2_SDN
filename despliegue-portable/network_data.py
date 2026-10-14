"""Change only an inventoried data interface, preserving management config."""
import argparse,copy,ipaddress,json,os,shutil,subprocess,time
from pathlib import Path
def run(*args):return subprocess.check_output(args,text=True)
def configure(c,node,backup):
    import yaml
    assert os.geteuid()==0
    n=c['nodes'][node];iface=n['data_interface'];mgmt=n['management_interface']
    assert iface!=mgmt and c['confirmed_after_inventory'] is True
    assert run('systemctl','is-active','systemd-networkd').strip()=='active'
    actual=json.loads(run('ip','-j','link','show',iface));assert actual[0]['address'].lower()==n['mac']
    before_addr=json.loads(run('ip','-j','-4','address','show',mgmt))
    before_route=[r for r in json.loads(run('ip','-j','-4','route')) if r.get('dev')==mgmt]
    candidates=[]
    for file in Path('/etc/netplan').glob('*.yaml'):
        data=yaml.safe_load(file.read_text()) or {}
        if iface in data.get('network',{}).get('ethernets',{}):candidates.append((file,data))
    assert len(candidates)==1,'Data interface must exist explicitly in exactly one Netplan YAML; review manually'
    file,data=candidates[0];old=copy.deepcopy(data);settings=data['network']['ethernets'][iface]
    assert not any(k in settings for k in ('match','set-name','routes','gateway4','nameservers')), 'Complex data NIC: manual review needed'
    assert data['network'].get('renderer','networkd')=='networkd'
    if node in ('h1','h2'):
        settings.pop('addresses',None);settings['dhcp4']=True;settings['dhcp-identifier']='mac'
        settings['dhcp4-overrides']={'use-routes':False,'use-dns':False,'use-hostname':False,'use-mtu':False}
    else:
        settings['dhcp4']=False;settings['addresses']=[n['ip']+'/'+str(ipaddress.ip_network(c['data_cidr']).prefixlen)]
    original=copy.deepcopy(old);original['network']['ethernets'].pop(iface)
    changed=copy.deepcopy(data);changed['network']['ethernets'].pop(iface)
    assert original==changed
    dest=Path(backup)/file.name;shutil.copy2(file,dest)
    try:
        file.write_text(yaml.safe_dump(data,sort_keys=False));file.chmod(0o600)
        run('netplan','generate');run('networkctl','reload');run('networkctl','reconfigure',iface);time.sleep(3)
        after_addr=json.loads(run('ip','-j','-4','address','show',mgmt))
        after_route=[r for r in json.loads(run('ip','-j','-4','route')) if r.get('dev')==mgmt]
        key=lambda rows:[(r['ifname'],[(a['local'],a['prefixlen']) for a in r['addr_info']]) for r in rows]
        assert key(before_addr)==key(after_addr) and before_route==after_route,'Management changed: stop and restore saved YAML via console'
    except Exception:
        shutil.copy2(dest,file);subprocess.run(['netplan','generate'])
        subprocess.run(['networkctl','reload']);subprocess.run(['networkctl','reconfigure',iface]);raise
    print('Data interface configured; management address and routes unchanged')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('node');p.add_argument('--config',default='topology.json');p.add_argument('--backup',required=True);a=p.parse_args()
    configure(json.loads(Path(a.config).read_text()),a.node,a.backup)
