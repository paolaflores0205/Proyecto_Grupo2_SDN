"""Install one node locally. Explicit clean-lab confirmation; no gateway support."""
import argparse,datetime,ipaddress,json,os,pwd,shutil,subprocess,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def output(*args):return subprocess.check_output(args,text=True).strip()
def write(path,text,mode=0o644):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf8');p.chmod(mode)
def unit(name,text):write('/etc/systemd/system/'+name+'.service',text)
def snapshot(node):
    dest=Path('/var/backups')/('sdn-portable-'+node+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    dest.mkdir(mode=0o700,exist_ok=False)
    for name,args in [('addresses.json',['ip','-j','address']),('routes.json',['ip','-j','route']),('units.txt',['systemctl','list-unit-files'])]:
        write(dest/name,output(*args)+'\n',0o600)
    with tarfile.open(dest/'configs.tgz','w:gz') as tar:
        for p in ('/etc/netplan','/etc/systemd/system','/etc/openvswitch'):
            if Path(p).exists():tar.add(p,arcname=p.lstrip('/'))
    if shutil.which('ovs-vsctl'):write(dest/'ovs.txt',output('ovs-vsctl','show'),0o600)
    return dest
def account(name):
    try:pwd.getpwnam(name)
    except KeyError:run('useradd','--system','--user-group','--no-create-home','--shell','/usr/sbin/nologin',name)
def cert(folder,ip,group):
    Path(folder).mkdir(parents=True,exist_ok=True)
    run('openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','365',
        '-keyout',folder+'/server.key','-out',folder+'/server.crt','-subj','/CN=SDN-Laboratorio',
        '-addext','subjectAltName=IP:'+ip,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run('chown','root:'+group,folder+'/server.key');Path(folder+'/server.key').chmod(0o640)
def copy_py(folder):
    Path(folder).mkdir(parents=True,exist_ok=True)
    for f in (ROOT/'source').glob('*.py'):shutil.copy2(f,Path(folder)/f.name)
def resource_unit(name,folder,script):
    unit(name,f'''[Unit]
Description=SDN educational resource {name}
After=network-online.target
Wants=network-online.target
[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory={folder}
ExecStart=/usr/bin/python3 {folder}/{script}
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
''')
def controller(c):
    account('sdnportal')
    for folder in ('/opt/sdn-portal-paso4','/opt/sdn-admin-paso7','/opt/sdn-floodlight'):copy_py(folder)
    for kind,dest in [('portal','/opt/sdn-portal-paso4'),('admin','/opt/sdn-admin-paso7')]:
        shutil.copytree(ROOT/'source'/kind,dest,dirs_exist_ok=True)
    shutil.copy2(ROOT/'vendor/floodlight.jar','/opt/sdn-floodlight/floodlight.jar')
    shutil.copy2(ROOT/'source/floodlight.properties','/opt/sdn-floodlight/floodlight_paso2.properties')
    Path('/var/lib/sdn-floodlight/sync').mkdir(parents=True,exist_ok=True)
    run('chown','-R','ubuntu:ubuntu','/var/lib/sdn-floodlight')
    from seed_database import seed
    write('/etc/mysql/mysql.conf.d/90-sdn-local.cnf','[mysqld]\nbind-address=127.0.0.1\nmysqlx-bind-address=127.0.0.1\n')
    run('systemctl','enable','--now','mysql');run('systemctl','restart','mysql');seed(ROOT,c)
    cert('/etc/sdn-portal-paso4',c['nodes']['controller']['ip'],'sdnportal')
    cert('/etc/sdn-admin-paso7',c['controller_management_ip'],'sdnportal')
    unit('sdn-floodlight','''[Unit]
Description=Floodlight 1.2 restricted R1/R2
After=network-online.target
Wants=network-online.target
[Service]
User=ubuntu
Group=ubuntu
StateDirectory=sdn-floodlight
WorkingDirectory=/var/lib/sdn-floodlight
ExecStart=/usr/bin/java -Xms128m -Xmx512m -jar /opt/sdn-floodlight/floodlight.jar -cf /opt/sdn-floodlight/floodlight_paso2.properties
ExecStartPost=/usr/bin/python3 /opt/sdn-portal-paso4/vnrt_avz7_red.py bootstrap
ExecStartPost=+/usr/bin/python3 /opt/sdn-portal-paso4/portable_observe.py
Restart=on-failure
RestartSec=5
TimeoutStartSec=100
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
[Install]
WantedBy=multi-user.target
''')
    unit('sdn-r1','''[Unit]
Description=R1/R2 Python adapter outside Floodlight
After=mysql.service sdn-floodlight.service
Requires=mysql.service
Wants=sdn-floodlight.service
PartOf=sdn-floodlight.service
[Service]
User=sdnportal
Group=sdnportal
WorkingDirectory=/opt/sdn-portal-paso4
ExecStart=/usr/bin/python3 /opt/sdn-portal-paso4/vnrt_avz7_adapter.py daemon
Restart=on-failure
RuntimeDirectory=sdn-r1
RuntimeDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    for name,folder,ip,port,module,config in [
        ('sdn-portal','/opt/sdn-portal-paso4',c['nodes']['controller']['ip'],443,'vnrt_avz7_portal','sdn-portal-paso4'),
        ('sdn-admin','/opt/sdn-admin-paso7',c['controller_management_ip'],8443,'vnrt_avz7_admin','sdn-admin-paso7')]:
        unit(name,f'''[Unit]
Description=SDN {name} HTTPS
After=mysql.service sdn-r1.service
Requires=mysql.service
Wants=sdn-r1.service
[Service]
User=sdnportal
Group=sdnportal
WorkingDirectory={folder}
ExecStart=/usr/bin/python3 -m gunicorn --workers 1 --threads 2 --bind {ip}:{port} --certfile /etc/{config}/server.crt --keyfile /etc/{config}/server.key --ssl-version 2 --access-logfile - --error-logfile - --timeout 30 {module}:app
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
''')
    iface=c['nodes']['controller']['data_interface']
    dhcp={'Dhcp4':{'interfaces-config':{'interfaces':[iface],'dhcp-socket-type':'raw'},
        'lease-database':{'type':'memfile','persist':True,'name':'/var/lib/kea/kea-leases4.csv'},
        'valid-lifetime':900,'renew-timer':300,'rebind-timer':600,'match-client-id':False,
        'host-reservation-identifiers':['hw-address'],'subnet4':[{'id':1,'subnet':c['data_cidr'],'interface':iface,
            'reservations-out-of-pool':True,'reservations':[{'hw-address':c['nodes'][h]['mac'],'ip-address':c['nodes'][h]['ip']} for h in ('h1','h2')]}],
        'loggers':[{'name':'kea-dhcp4','severity':'INFO','output_options':[{'output':'stdout'}]}]}}
    write('/etc/kea/kea-dhcp4.conf',json.dumps(dhcp,indent=2))
    for folder in ('/var/lib/kea','/var/log/kea','/run/lock/kea'):Path(folder).mkdir(parents=True,exist_ok=True)
    unit('sdn-dhcp','''[Unit]
Description=Kea DHCP data interface only
After=network-online.target sdn-floodlight.service
Wants=network-online.target sdn-floodlight.service
[Service]
Environment=KEA_LOCKFILE_DIR=/run/lock/kea
ExecStart=/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
Restart=on-failure
RuntimeDirectory=kea
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/kea /var/log/kea /run/kea /run/lock/kea
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
''')
    run('kea-dhcp4','-t','/etc/kea/kea-dhcp4.conf')
    run('systemctl','daemon-reload')
    run('systemctl','enable','--now','sdn-floodlight','sdn-r1','sdn-portal','sdn-admin','sdn-dhcp')
def switches(c,node):
    s=c['switches'][node];bridge=s['bridge']
    for p,iface in s['ports'].items():
        assert iface!=s['management_interface']
        addresses=json.loads(output('ip','-j','address','show',iface))[0]['addr_info']
        assert not any(a['family']=='inet' or a.get('scope')!='link' for a in addresses),'Data switch NIC has IP: review manually'
    exists=subprocess.run(['ovs-vsctl','br-exists',bridge]).returncode==0
    if exists:
        actual=output('ovs-vsctl','get','bridge',bridge,'datapath_id').strip('"')
        assert actual==s['dpid'].replace(':',''),'Existing DPID differs from inventoried DPID'
        existing=set(output('ovs-vsctl','list-ports',bridge).splitlines())
        assert existing<=set(s['ports'].values()),'Unknown bridge port: not touching this bridge'
    else:run('ovs-vsctl','add-br',bridge)
    run('ovs-vsctl','set','bridge',bridge,'other-config:datapath-id='+s['dpid'].replace(':',''),'protocols=OpenFlow13')
    for p,iface in s['ports'].items():
        run('ovs-vsctl','--may-exist','add-port',bridge,iface,'--','set','Interface',iface,'ofport_request='+p)
        run('ip','link','set',iface,'up')
    run('ip','link','set',bridge,'up')
    run('ovs-vsctl','set-fail-mode',bridge,'secure')
    run('ovs-vsctl','set-controller',bridge,'tcp:'+c['controller_management_ip']+':6653')
    for p,iface in s['ports'].items():assert output('ovs-vsctl','get','Interface',iface,'ofport')==p
    print('Bridge configured; management unchanged. Floodlight will clear bridge tables at master handshake.')
def main():
    p=argparse.ArgumentParser();p.add_argument('node',choices=['controller','sw1','sw2','sw3','h1','h2','h3','h4']);p.add_argument('--confirm-clean-lab',action='store_true');a=p.parse_args()
    assert os.geteuid()==0 and a.confirm_clean_lab,'Use sudo and explicit clean-lab confirmation'
    c=json.loads((ROOT/'topology.json').read_text());assert c['confirmed_after_inventory'] is True
    node=a.node;pwd.getpwnam('ubuntu')
    if not node.startswith('sw'):
        assert not any(Path(p).exists() for p in ['/opt/sdn-portal-paso4','/opt/sdn-admin-paso7','/opt/sdn-lms-paso3','/opt/sdn-notas-paso6','/opt/sdn-floodlight']), 'Existing project deployment: do not overwrite; manual migration required'
    assert not list(Path('/etc/systemd/system').glob('sdn-*.service')),'Existing SDN services: manual migration required'
    if node=='controller' and shutil.which('mysql'):
        result=subprocess.run(['mysql','--protocol=socket','--batch','--skip-column-names','-e',"SELECT schema_name FROM information_schema.schemata WHERE schema_name='sdn_g2'"],capture_output=True,text=True)
        assert result.returncode==0 and not result.stdout.strip(),'Existing database or unavailable SQL: review before installing'
    backup=snapshot(node);print('LOCAL_BACKUP',backup)
    packages=['python3','python3-yaml','openssl']
    if node.startswith('sw'):packages+=['openvswitch-switch']
    if node=='controller':
        assert not output('ss','-H','-lun','sport = :67'),'DHCP port already occupied; do not start a second server'
        run('systemctl','mask','kea-dhcp4-server.service')
        packages+=['default-jre-headless','mysql-server','python3-flask','python3-gunicorn','python3-pymysql','kea-dhcp4-server']
    run('apt-get','update');run('apt-get','install','-y','--no-install-recommends',*packages,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
    write('/etc/sdn-g2/topology.json',json.dumps(c,indent=2))
    if node.startswith('sw'):switches(c,node);return
    from network_data import configure
    configure(c,node,backup)
    if node=='controller':controller(c)
    elif node in ('h3','h4'):
        folder='/opt/sdn-lms-paso3' if node=='h3' else '/opt/sdn-notas-paso6'
        Path(folder).mkdir(parents=True);cert(folder,c['nodes'][node]['ip'],'ubuntu')
        names=[('sdn-lms','vnrt_lms_https_paso3.py')] if node=='h3' else [('sdn-notas','vnrt_notas_https_paso6.py'),('sdn-recurso-administrativo','vnrt_recurso_administrativo.py')]
        for name,script in names:
            shutil.copy2(ROOT/'source'/script,folder+'/'+script);resource_unit(name,folder,script)
        run('systemctl','daemon-reload');run('systemctl','enable','--now',*[name for name,script in names])
    else:
        shutil.copy2(ROOT/'smoke_test.py','/etc/sdn-g2/smoke_test.py')
        print('DHCP requested. Wait for lease and provision public trust.pem before HTTPS tests.')
if __name__=='__main__':main()
