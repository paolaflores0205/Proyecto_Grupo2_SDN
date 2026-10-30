"""Run on controller as root. Staged code is separate; rollback never restores old sessions."""
import argparse,json,pathlib,re,subprocess,sys,time
APP=pathlib.Path('/opt/sdn-portal-paso4')
def run(*args,input=None):
    return subprocess.run(args,input=input,text=True,capture_output=True,check=True).stdout
def sql(text):return run('mysql','--protocol=socket','sdn_g2',input=text)
def revision_schema():
    sql('''CREATE TABLE IF NOT EXISTS policy_revision (id TINYINT UNSIGNED PRIMARY KEY,revision BIGINT UNSIGNED NOT NULL);
        INSERT IGNORE INTO policy_revision VALUES(1,1);''')
    conditions={
        'sessions':"NOT(OLD.revoked_at <=> NEW.revoked_at) OR NOT(OLD.expires_at <=> NEW.expires_at) OR NOT(OLD.role_id <=> NEW.role_id) OR NOT(OLD.terminal_ip <=> NEW.terminal_ip) OR NOT(OLD.terminal_mac <=> NEW.terminal_mac) OR NOT(OLD.switch_dpid <=> NEW.switch_dpid) OR NOT(OLD.in_port <=> NEW.in_port)",
        'role_permissions':'OLD.allowed <> NEW.allowed',
        'users':'OLD.active <> NEW.active OR OLD.role_id <> NEW.role_id',
        'resources':"NOT(OLD.ip_address <=> NEW.ip_address) OR OLD.port <> NEW.port OR OLD.transport <> NEW.transport OR OLD.deployment_state <> NEW.deployment_state",
        'roles':'OLD.code <> NEW.code'}
    for table,condition in conditions.items():
        for event in ('INSERT','UPDATE','DELETE'):
            name='sdn_mt_revision_'+table+'_'+event.lower()
            body=('IF '+condition+' THEN UPDATE policy_revision SET revision=revision+1 WHERE id=1; END IF;' if event=='UPDATE' else 'UPDATE policy_revision SET revision=revision+1 WHERE id=1;')
            sql('DROP TRIGGER IF EXISTS '+name+';\nDELIMITER $$\nCREATE TRIGGER '+name+' AFTER '+event+' ON '+table+' FOR EACH ROW BEGIN '+body+' END$$\nDELIMITER ;\n')
    cfg=json.loads(pathlib.Path('/etc/sdn-portal-paso4/config.json').read_text())
    user=cfg['db_user'];assert re.fullmatch(r'[A-Za-z0-9_]+',user)
    sql("GRANT SELECT ON sdn_g2.policy_revision TO '"+user+"'@'127.0.0.1';")

def overrides():
    sys.path.insert(0,str(APP));import vnrt_avz7_red as current
    portal_ip=current.HOSTS['controller'][3]
    observer=APP/('vnrt_avz7_observe.py' if (APP/'vnrt_avz7_observe.py').exists() else 'portable_observe.py')
    content={
      'sdn-floodlight':'[Service]\nExecStartPost=\nExecStartPost=/usr/bin/python3 /opt/sdn-portal-paso4/vnrt_mt_red.py bootstrap\nExecStartPost=+/usr/bin/python3 '+str(observer)+'\n',
      'sdn-r1':'[Service]\nExecStart=\nExecStart=/usr/bin/python3 /opt/sdn-portal-paso4/vnrt_mt_adapter.py\n',
      'sdn-portal':'[Service]\nExecStart=\nExecStart=/usr/bin/python3 -m gunicorn --workers 1 --threads 2 --bind '+portal_ip+':443 --certfile /etc/sdn-portal-paso4/server.crt --keyfile /etc/sdn-portal-paso4/server.key --ssl-version 2 --access-logfile - --error-logfile - --timeout 30 vnrt_mt_portal:app\n'}
    for service,text in content.items():
        folder=pathlib.Path('/etc/systemd/system')/(service+'.service.d');folder.mkdir(exist_ok=True)
        (folder/'80-multitabla.conf').write_text(text)

def rollback():
    run('systemctl','stop','sdn-portal','sdn-r1')
    sys.path.insert(0,str(APP));import vnrt_mt_red as red
    red.remove([n for n in red.stored_names() if n.startswith(red.P)])
    for service in ('sdn-floodlight','sdn-r1','sdn-portal'):
        path=pathlib.Path('/etc/systemd/system')/(service+'.service.d')/'80-multitabla.conf'
        if path.exists():path.unlink()
    run('systemctl','daemon-reload')
    run('python3',str(APP/'vnrt_avz7_red.py'),'bootstrap')
    run('systemctl','start','sdn-r1','sdn-portal')
    print('ROLLED_BACK_TO_VERIFIED_TABLE0')

def cutover():
    # No credential, role or resource matrix is changed by the migration.
    live=int(sql('SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);').splitlines()[-1])
    if live:raise RuntimeError('Active sessions detected; explicit controlled logout required before cutover')
    revision_schema()
    run('systemctl','stop','sdn-portal','sdn-r1')
    try:
        run('python3',str(APP/'vnrt_mt_red.py'),'bootstrap')
        overrides();run('systemctl','daemon-reload');run('systemctl','start','sdn-r1','sdn-portal')
        time.sleep(2)
        state=run('systemctl','is-active','sdn-r1','sdn-portal','sdn-floodlight')
        if state.split()!=['active']*3:raise RuntimeError('Services not active')
        run('python3',str(APP/'vnrt_mt_red.py'),'verify')
        print('MULTITABLE_CUTOVER_VERIFIED')
    except Exception:
        rollback();raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['cutover','rollback']);a=parser.parse_args()
    globals()[a.action]()
