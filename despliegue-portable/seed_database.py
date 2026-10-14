"""Fresh schema only. Generates new passwords locally, never copies Matthew's data."""
import json,os,pwd,secrets,subprocess
from pathlib import Path
def seed(root,c):
    import pymysql
    from werkzeug.security import generate_password_hash
    conn=pymysql.connect(unix_socket='/var/run/mysqld/mysqld.sock',user='root',autocommit=True)
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='sdn_g2'")
        assert cur.fetchone()[0]==0,'Existing sdn_g2 database: refusing replacement'
        cur.execute("SELECT COUNT(*) FROM mysql.user WHERE User IN ('sdn_portal','sdn_dti')")
        assert cur.fetchone()[0]==0,'Existing SQL app accounts: manual migration required'
        cur.execute('CREATE DATABASE sdn_g2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
    subprocess.run(['mysql','--protocol=socket','sdn_g2'],input=(root/'schema.sql').read_text(),text=True,check=True)
    conn.select_db('sdn_g2');accounts=[];roles={};resources={};labels={'estudiante':'Estudiante','docente':'Docente','administrativo':'Administrativo','visitante':'Visitante'}
    with conn.cursor() as cur:
        for role,label in labels.items():
            cur.execute('INSERT INTO roles(code,label) VALUES(%s,%s)',(role,label));roles[role]=cur.lastrowid
            password=secrets.token_urlsafe(18);username=role+'_demo'
            cur.execute('INSERT INTO users(username,display_name,password_hash,role_id) VALUES(%s,%s,%s,%s)',(username,label+' de prueba',generate_password_hash(password,method='scrypt'),roles[role]))
            accounts.append({'username':username,'password':password,'role':role})
        for code,node,label,port,privileged in [('lms','h3','LMS',443,0),('notas','h4','Notas',443,1),('administracion','h4','Sistema administrativo',8443,1)]:
            cur.execute("INSERT INTO resources(code,label,ip_address,transport,port,privileged,deployment_state) VALUES(%s,%s,%s,'TCP',%s,%s,'active')",(code,label,c['nodes'][node]['ip'],port,privileged));resources[code]=cur.lastrowid
        for role,rid in roles.items():
            for code,xid in resources.items():
                allowed=(role in ('estudiante','docente') and code=='lms') or (role=='docente' and code=='notas') or (role=='administrativo' and code=='administracion')
                cur.execute('INSERT INTO role_permissions VALUES(%s,%s,%s)',(rid,xid,int(allowed)))
        password=secrets.token_urlsafe(18);dti={'username':'dti_demo','password':password}
        cur.execute('INSERT INTO admin_accounts(username,password_hash) VALUES(%s,%s)',(dti['username'],generate_password_hash(password,method='scrypt')))
        for user,folder in [('sdn_portal','sdn-portal-paso4'),('sdn_dti','sdn-admin-paso7')]:
            password=secrets.token_urlsafe(32)
            cur.execute('CREATE USER %s@%s IDENTIFIED BY %s',(user,'127.0.0.1',password))
            config={'db_user':user,'db_password':password,'secret_key':secrets.token_urlsafe(48)}
            f=Path('/etc')/folder/'config.json';f.parent.mkdir(exist_ok=True)
            f.write_text(json.dumps(config));os.chown(f,0,pwd.getpwnam('sdnportal').pw_gid);f.chmod(0o640)
        portal=['GRANT SELECT ON sdn_g2.users TO sdn_portal@127.0.0.1',
            'GRANT SELECT ON sdn_g2.roles TO sdn_portal@127.0.0.1','GRANT SELECT ON sdn_g2.resources TO sdn_portal@127.0.0.1',
            'GRANT SELECT ON sdn_g2.role_permissions TO sdn_portal@127.0.0.1',
            'GRANT SELECT,INSERT,UPDATE ON sdn_g2.sessions TO sdn_portal@127.0.0.1',
            'GRANT SELECT,INSERT ON sdn_g2.auth_events TO sdn_portal@127.0.0.1',
            'GRANT SELECT,INSERT,UPDATE ON sdn_g2.network_rules TO sdn_portal@127.0.0.1']
        admin=['GRANT SELECT ON sdn_g2.admin_accounts TO sdn_dti@127.0.0.1',
            'GRANT SELECT,INSERT,UPDATE (revoked_at) ON sdn_g2.admin_sessions TO sdn_dti@127.0.0.1',
            'GRANT SELECT,INSERT ON sdn_g2.admin_events TO sdn_dti@127.0.0.1',
            'GRANT SELECT ON sdn_g2.auth_events TO sdn_dti@127.0.0.1',
            'GRANT SELECT ON sdn_g2.roles TO sdn_dti@127.0.0.1',
            'GRANT SELECT ON sdn_g2.resources TO sdn_dti@127.0.0.1',
            'GRANT SELECT,UPDATE (allowed) ON sdn_g2.role_permissions TO sdn_dti@127.0.0.1',
            'GRANT SELECT (id,username,display_name,role_id,active),UPDATE (role_id,active) ON sdn_g2.users TO sdn_dti@127.0.0.1',
            'GRANT SELECT (token_hash,user_id,terminal_ip,created_at,expires_at,revoked_at,network_state,session_state,enforcement_state),UPDATE (revoked_at,network_state,session_state,enforcement_state) ON sdn_g2.sessions TO sdn_dti@127.0.0.1']
        for statement in portal+admin:
            statement=statement.replace(' TO sdn_portal@127.0.0.1'," TO 'sdn_portal'@'127.0.0.1'").replace(' TO sdn_dti@127.0.0.1'," TO 'sdn_dti'@'127.0.0.1'")
            cur.execute(statement)
    conn.close()
    directory=Path('/var/lib/sdn-g2/private');directory.mkdir(parents=True,exist_ok=True);directory.chmod(0o700)
    for name,value in [('usuarios-prueba.json',accounts),('credenciales-dti.json',dti)]:
        f=directory/name;f.write_text(json.dumps(value,indent=2));f.chmod(0o600)
    print('Fresh database seeded; new credentials saved privately in /var/lib/sdn-g2/private/')
if __name__=='__main__':
    root=Path(__file__).resolve().parent;seed(root,json.loads((root/'topology.json').read_text()))
