"""Real portal and dataplane checks. Passwords/cookies remain in memory only."""
import argparse,json,pathlib,shlex,time
import inventario as inv
HERE=pathlib.Path(__file__).resolve().parent
CLIENT_CODE=(HERE/'cliente.py').read_text(encoding='utf-8')
EXPECTED={'estudiante':{'lms'},'docente':{'lms','notas'},'administrativo':{'administracion'},'visitante':set()}
LABEL={'estudiante':'Estudiante','docente':'Docente','administrativo':'Administrativo','visitante':'Visitante'}
class Tests:
    def __init__(self):self.clients={};self.checks={};self.details={}
    def preflight(self):
        if self.sql('SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);')!='0':raise RuntimeError('Hay sesiones activas; no iniciar pruebas')
        policy=self.sql("SELECT p.allowed FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id WHERE r.code='docente' AND x.code='notas';")
        if policy!='1':raise RuntimeError('La matriz inicial debe permitir docente/Notas; no se modificó la política')
    def node(self,name):
        if name not in self.clients:self.clients[name]=inv.connect(name)
        return self.clients[name]
    def sql(self,text):
        r=inv.command(self.node('controller'),'mysql --protocol=socket --batch --skip-column-names sdn_g2 -e '+shlex.quote(text),True)
        if r['code']:raise RuntimeError(r['stderr'])
        return r['stdout'].strip()
    def call(self,host,mode,state=None,account=None):
        payload={'mode':mode,'network':inv.config()['network']}
        if state:payload['state']=state
        if account:payload.update(account=account,label=LABEL[account['role']])
        inp,out,err=self.node(host).exec_command('python3 -c '+shlex.quote(CLIENT_CODE),timeout=40)
        inp.write(json.dumps(payload));inp.flush();inp.channel.shutdown_write()
        output=out.read().decode();errors=err.read().decode();code=out.channel.recv_exit_status()
        if code:raise RuntimeError(host+' probe failed: '+errors[-600:])
        return json.loads(output)
    def access(self,result,allowed):return all(result['access'][code]==(200 if code in allowed else 0) for code in ('lms','notas','administracion'))
    def account_map(self):
        r=inv.command(self.node('controller'),'cat '+shlex.quote(inv.config()['network']['test_accounts_path']),True)
        if r['code']:raise RuntimeError('Cannot read existing test accounts')
        return {a['role']:a for a in json.loads(r['stdout'])}
    def check(self,name,ok,detail=None):
        self.checks[name]=bool(ok)
        if detail is not None:self.details[name]=detail
        print(json.dumps({'check':name,'passed':bool(ok)}),flush=True)
        if not ok:raise RuntimeError('Test failed: '+name)
    def run(self,full=False):
        self.preflight()
        accounts=self.account_map();initial=self.call('h1','initial')
        self.check('baseline_health_metadata',initial['portal'] and initial['health'].get('metadata') is True,initial['health'])
        self.check('prelogin_resources_denied',self.access(initial,set()),initial['access'])
        for host in (('h1','h2') if full else ('h1',)):
            for role in (EXPECTED if full else ('estudiante',)):
                logged=self.call(host,'login',account=accounts[role])
                self.check(host+'_'+role+'_matrix',logged['code']==200 and logged['panel'] and logged['role_match'] and self.access(logged,EXPECTED[role]),logged['access'])
                counts=self.sql("SELECT resource_code,COUNT(*) FROM network_rules WHERE enforcement_state='VERIFIED' GROUP BY resource_code;")
                self.details[host+'_'+role+'_counts']=counts
                loggedout=self.call(host,'logout',state=logged['state'])
                self.check(host+'_'+role+'_logout',loggedout['logged_out'] and self.access(loggedout,set()))
        if full:
            one=self.call('h1','login',account=accounts['docente']);two=self.call('h2','login',account=accounts['estudiante'])
            self.check('two_independent_sessions',self.access(one,EXPECTED['docente']) and self.access(two,EXPECTED['estudiante']))
            try:
                self.sql("UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=0 WHERE r.code='docente' AND x.code='notas';")
                withdrawn=self.call('h1','status',state=one['state'])
                self.check('selective_notas_revocation_keeps_lms',withdrawn['panel'] and self.access(withdrawn,{'lms'}),withdrawn['access'])
                peer=self.call('h2','status',state=two['state']);self.check('selective_revocation_preserves_peer',peer['panel'] and self.access(peer,{'lms'}))
            finally:self.sql("UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=1 WHERE r.code='docente' AND x.code='notas';")
            restored=self.call('h1','status',state=one['state']);self.check('permission_restored_after_fresh_evaluation',restored['panel'] and self.access(restored,{'lms','notas'}))
            self.call('h1','logout',state=one['state'])
            peer=self.call('h2','status',state=two['state']);self.check('logout_preserves_peer',peer['panel'] and self.access(peer,{'lms'}))
            self.call('h2','logout',state=two['state'])
        self.check('final_no_individual_rules',self.sql("SELECT COUNT(*) FROM network_rules WHERE enforcement_state='VERIFIED';")=='0')
    def close(self):
        for client in self.clients.values():client.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--ejecutar',action='store_true',required=True);p.add_argument('--full',action='store_true');args=p.parse_args();tests=Tests()
    try:tests.run(args.full)
    finally:
        inv.OUT.mkdir(parents=True,exist_ok=True)
        (inv.OUT/('pruebas_completas.json' if args.full else 'piloto.json')).write_text(json.dumps({'checks':tests.checks,'details':tests.details,'credentials_logged':False},indent=2),encoding='utf-8')
        tests.close()
