"""Observed DTI-to-denial latency; not physical DROP timestamp or capacity."""
import pathlib,sys,os,json,time,shlex,concurrent.futures,datetime,random,argparse,statistics,math
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'pruebas/r2'))
from pruebas import Tests
import inventario as inv
WORKER=(HERE/'worker.py').read_text(encoding='utf-8')
TIMEOUT=.35;INTERVAL=.1;DEADLINE=15
utc=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
class RPC:
 def __init__(self,host,cfg,sudo=False):
  self.client=inv.connect(host)
  cmd='python3 -u -c '+shlex.quote(WORKER)
  if sudo:cmd='sudo -S -p "" '+cmd
  self.i,self.o,self.e=self.client.exec_command(cmd,timeout=30)
  if sudo:self.i.write(os.environ['VNRT_SUDO_PASSWORD']+'\n');self.i.flush()
  self.i.write(json.dumps(dict(cfg,network=inv.config()['network']))+'\n');self.i.flush()
  ready=self.o.readline()
  if not ready:raise RuntimeError(host+' worker unavailable: '+self.e.read().decode()[-300:])
  if not json.loads(ready).get('ready'):raise RuntimeError('Worker not ready')
 def call(self,p):
  self.i.write(json.dumps(p)+'\n');self.i.flush()
  raw=self.o.readline()
  if not raw:raise RuntimeError('Worker closed')
  result=json.loads(raw)
  if 'worker_error' in result:raise RuntimeError(result['worker_error'])
  return result
 def close(self):
  try:self.i.write('{"operation":"close"}\n');self.i.flush()
  except Exception:pass
  self.client.close()

class Bench:
 def __init__(self):self.t=Tests();self.workers=[];self.states={};self.record={'started_utc':utc(),'protocol':{'origin':'Windows orchestration clock, time.perf_counter','t0':'Immediately before dispatching authenticated DTI POST /policy over a persistent SSH worker','t1':'Completion of second consecutive failed fresh HTTPS /health request from h1 to Notas','interval_seconds':INTERVAL,'per_request_timeout_seconds':TIMEOUT,'confirmation_failures':2,'deadline_seconds':DEADLINE,'metric':'observed denial confirmation, includes SSH/HTTP/polling and failure-detection overhead','not_measured':['physical DROP timestamp','max concurrency','campus capacity','TCAM']},'pilot':[],'trials':[],'credentials_logged':False}
 def save(self):
  inv.OUT.mkdir(parents=True,exist_ok=True)
  (inv.OUT/'mediciones.json').write_text(json.dumps(self.record,indent=2),encoding='utf-8')
 def probe(self,worker,resource):return worker.call({'resource':resource})
 def check_rules(self):
  result={}
  for sw in ['sw2','sw3']:
   r=inv.command(self.t.node(sw),'ovs-ofctl -O OpenFlow13 dump-flows '+sw,True)
   if r['code']:raise RuntimeError('Cannot inspect OVS '+sw+': exit='+str(r['code'])+' '+r['stderr'][-300:])
   result[sw]={'priority500_notas':sum('priority=500' in l and inv.config()['network']['resources']['notas']['ip'] in l and ('tp_dst=443' in l or 'tp_src=443' in l) for l in r['stdout'].splitlines())}
  return result
 def setup(self):
  if self.t.sql('SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);')!='0':raise RuntimeError('Live sessions exist; stop without replacing them')
  value=self.t.sql("SELECT p.allowed,r.id,x.id FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id WHERE r.code='docente' AND x.code='notas';").split('\t')
  if value[0]!='1':raise RuntimeError('Original docente/Notas policy is not allowed; stop')
  self.original_allowed=1
  self.record['environment']={}
  for node in ['controller','h1','h2']:
   self.record['environment'][node]=inv.command(self.t.node(node),'hostname; date -Is; nproc; free -m; df -h /')['stdout']
  # Known project test fixture, read only for the authorized role tests.
  accounts=self.t.account_map()
  self.record['role_preconditions']={}
  for host,role in [('h1','docente'),('h2','estudiante')]:
   logged=self.t.call(host,'login',account=accounts[role]);self.states[host]=logged['state']
   self.record['role_preconditions'][host]={k:v for k,v in logged.items() if k!='state'}
   self.save()
   if not logged['panel'] or not logged['role_match'] or not self.t.access(logged,{'lms','notas'} if role=='docente' else {'lms'}):raise RuntimeError('Role precondition failed')
  self.dti=RPC('controller',{'mode':'dti','role_id':int(value[1]),'resource_id':int(value[2])},True);self.workers.append(self.dti)
  self.h1=RPC('h1',{'mode':'probe','client_ip':inv.config()['network']['clients']['h1'],'timeout':TIMEOUT});self.workers.append(self.h1)
  self.h2=RPC('h2',{'mode':'probe','client_ip':inv.config()['network']['clients']['h2'],'timeout':TIMEOUT});self.workers.append(self.h2)
  initial=self.check_rules()
  if any(v['priority500_notas']!=2 for v in initial.values()):raise RuntimeError('Expected Notas ida/retorno rules not present')
  self.record['initial_rules']=initial;self.save()
 def trial(self,index,pilot=False):
  r={'id':('piloto-' if pilot else 'ensayo-')+str(index).zfill(2),'started_utc':utc(),'preconditions':{},'probes':[]}
  self.record['current_attempt']=r
  for name,w,resource in [('h1_notas',self.h1,'notas'),('h1_lms',self.h1,'lms'),('h2_lms',self.h2,'lms')]:
   r['preconditions'][name]=self.probe(w,resource)
  if not all(v['useful'] for v in r['preconditions'].values()):
   r.update(success=False,error='Positive-control precondition failed');return r
  # Phase jitter avoids always testing at one point in the renewal cycle.
  time.sleep(random.Random(2200+index+int(pilot)*100).uniform(.15,.65))
  shared={}
  def revoke():
   shared['t0']=time.perf_counter()
   response=self.dti.call({'allowed':0,'expected':1})
   return {'response':response,'response_ms':(time.perf_counter()-shared['t0'])*1000}
  try:
   with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    future=pool.submit(revoke)
    while 't0' not in shared:time.sleep(.001)
    consecutive=0;first_failed=None
    while time.perf_counter()-shared['t0']<DEADLINE:
     begin=time.perf_counter();p=self.probe(self.h1,'notas');end=time.perf_counter()
     r['probes'].append(dict(p,start_ms=(begin-shared['t0'])*1000,end_ms=(end-shared['t0'])*1000))
     if p['status']==0:
      if not consecutive:first_failed=(end-shared['t0'])*1000
      consecutive+=1
     else:consecutive=0;first_failed=None
     if consecutive>=2:
      r['first_failure_ms']=first_failed;r['confirmation_ms']=(end-shared['t0'])*1000;break
     time.sleep(INTERVAL)
    r['dti']=future.result(timeout=25)
   r['controls_after']={'h1_lms':self.probe(self.h1,'lms'),'h2_lms':self.probe(self.h2,'lms')}
   r['rules_after']=self.check_rules()
   r['success']=bool('confirmation_ms' in r and r['dti']['response']['status']==200 and r['dti']['response']['dashboard'] and all(v['useful'] for v in r['controls_after'].values()) and all(v['priority500_notas']==0 for v in r['rules_after'].values()))
   if not r['success']:r['error']='Expected effect/control/rules or DTI response failed'
  except Exception as error:
   r.update(success=False,error=type(error).__name__+': '+str(error))
  finally:
   # Restore only the exact policy changed by this trial.
   restored=self.dti.call({'allowed':1,'expected':0});r['restore_dti']=restored
   deadline=time.perf_counter()+10
   while time.perf_counter()<deadline:
    positive=self.probe(self.h1,'notas')
    if positive['useful']:break
    time.sleep(INTERVAL)
   r['restore_notas']=positive
   if not restored['dashboard'] or not positive['useful']:r.update(success=False,error='Restore did not recover positive control')
  r['finished_utc']=utc();self.record.pop('current_attempt',None);return r
 def cleanup(self):
  errors=[]
  try:
   if getattr(self,'original_allowed',None)==1:
    self.t.sql("UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=1 WHERE r.code='docente' AND x.code='notas';")
  except Exception as e:errors.append('restore policy: '+type(e).__name__)
  if hasattr(self,'dti'):
   try:self.record['dti_logout']=self.dti.call({'operation':'logout'})
   except Exception as e:errors.append('DTI logout: '+type(e).__name__)
  for w in self.workers:w.close()
  for host,state in self.states.items():
   try:
    result=self.t.call(host,'logout',state=state)
    if not result['logged_out']:errors.append(host+' logout failed')
   except Exception as e:errors.append(host+' cleanup: '+type(e).__name__)
  try:
   self.record['final_state']={'live_sessions':self.t.sql('SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);'),'verified_individual_rules':self.t.sql("SELECT COUNT(*) FROM network_rules WHERE enforcement_state='VERIFIED';"),'docente_notas_allowed':self.t.sql("SELECT p.allowed FROM role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id WHERE r.code='docente' AND x.code='notas';"),'services':inv.command(self.t.node('controller'),'systemctl is-active sdn-floodlight sdn-r1 sdn-portal sdn-admin mysql sdn-dhcp')['stdout'],'disk':inv.command(self.t.node('controller'),'df -h /')['stdout']}
  except Exception as e:errors.append('final state: '+type(e).__name__)
  self.record['cleanup_errors']=errors;self.record['finished_utc']=utc();self.save();self.t.close()
 def summary(self):
  trials=self.record['trials'];valid=[r['confirmation_ms'] for r in trials if r.get('success')]
  def quantile_nearest(values,p):return sorted(values)[max(0,math.ceil(len(values)*p)-1)]
  summary={'attempts':len(trials),'successes':len(valid),'failures':len(trials)-len(valid),'pilot_excluded':True,'metric':'Observed DTI order to confirmed denial of fresh HTTPS requests','unit':'ms','p95_method':'nearest-rank ceil(0.95*n)','timeout_ms':TIMEOUT*1000,'poll_interval_ms':INTERVAL*1000}
  if valid:summary.update(mean_ms=statistics.mean(valid),median_ms=statistics.median(valid),min_ms=min(valid),max_ms=max(valid),p95_ms=quantile_nearest(valid,.95),stdev_sample_ms=statistics.stdev(valid) if len(valid)>1 else None,lms_h1_successes=sum(r['controls_after']['h1_lms']['useful'] for r in trials if 'controls_after' in r),lms_h2_successes=sum(r['controls_after']['h2_lms']['useful'] for r in trials if 'controls_after' in r))
  self.record['summary']=summary;self.save();print(json.dumps({'summary':summary}),flush=True)

if __name__=='__main__':
 args=argparse.ArgumentParser();args.add_argument('--ejecutar',action='store_true',required=True);args.add_argument('--trials',type=int,default=30);args=args.parse_args()
 b=Bench()
 try:
  b.setup();pilot=b.trial(1,True);b.record['pilot'].append(pilot);b.save();print(json.dumps({'pilot_success':pilot['success'],'confirmation_ms':pilot.get('confirmation_ms')}),flush=True)
  if not pilot['success']:raise RuntimeError('Pilot failed; do not continue to a campaign')
  for index in range(1,args.trials+1):
   trial=b.trial(index);b.record['trials'].append(trial);b.save();print(json.dumps({'id':trial['id'],'success':trial['success'],'confirmation_ms':trial.get('confirmation_ms'),'error':trial.get('error')}),flush=True)
   if not trial['success']:raise RuntimeError('Stop on failed trial; retain it in the denominator')
  b.summary()
 except Exception as e:
  b.record['run_error']=type(e).__name__+': '+str(e);b.save();print(json.dumps({'run_error':b.record['run_error']}),flush=True)
 finally:b.cleanup()
