"""Controlled fault injection; restores teacher policy and adapter in finally blocks."""
import json,pathlib,shlex,time
from pruebas import Tests,EXPECTED
import inventario as inv

LATE=r'''
import json,subprocess,sys
sys.path.insert(0,'/opt/sdn-portal-paso4')
import vnrt_mt_adapter as adapter
red=adapter.red;original=red.push;injected=[False];worker=adapter.Reconciler()
def delayed(f):
    if not injected[0] and '-notas-' in f['name']:
        injected[0]=True
        # This job was planned while allowed. Withdraw after its guard, before delivery.
        subprocess.run(['mysql','--protocol=socket','sdn_g2','-e',"UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=0 WHERE r.code='docente' AND x.code='notas'"],check=True,capture_output=True)
    original(f)
red.push=delayed
try:
    worker.sync();raise AssertionError('Obsolete job was not rejected')
except RuntimeError as e:
    if 'Stale authorization revision' not in str(e):raise
    worker.fail_closed()
    rows=red.all_actual()
    count=sum(red.number(r['priority'])==500 for v in rows.values() for r in v)
    print(json.dumps({'injected':injected[0],'obsolete_job_rejected':True,'remaining_individual_rules':count}))
'''

PARTIAL=r'''
import json,sys
sys.path.insert(0,'/opt/sdn-portal-paso4')
import vnrt_mt_adapter as adapter
red=adapter.red;original=red.push;count=[0];worker=adapter.Reconciler()
def faulty(f):
    count[0]+=1
    if count[0]==2:raise RuntimeError('Injected partial installation')
    original(f)
red.push=faulty
try:
    worker.sync();raise AssertionError('Fault not injected')
except RuntimeError as e:
    if 'Injected partial' not in str(e):raise
    worker.fail_closed()
    rows=red.all_actual();left=sum(red.number(r['priority'])==500 for v in rows.values() for r in v)
    print(json.dumps({'partial_injected':True,'remaining_individual_rules':left}))
'''

def main(t):
    t.preflight()
    a=t.account_map();teacher=t.call('h1','login',account=a['docente'])
    t.check('teacher_ready_for_consistency',teacher['panel'] and t.access(teacher,EXPECTED['docente']))
    try:
        r=inv.command(t.node('controller'),'systemctl stop sdn-r1',True)
        if r['code']:raise RuntimeError(r['stderr'])
        r=inv.command(t.node('controller'),'python3 -c '+shlex.quote(LATE),True)
        if r['code']:raise RuntimeError(r['stderr'])
        detail=json.loads(r['stdout']);t.check('late_obsolete_job_retired',detail['obsolete_job_rejected'] and detail['remaining_individual_rules']==0,detail)
    finally:inv.command(t.node('controller'),'systemctl start sdn-r1',True)
    time.sleep(2)
    denied=t.call('h1','status',state=teacher['state'])
    t.check('late_job_does_not_restore_notas',denied['panel'] and t.access(denied,{'lms'}),denied['access'])
    t.sql("UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=1 WHERE r.code='docente' AND x.code='notas';")
    t.check('fresh_policy_reenables_notas',t.access(t.call('h1','status',state=teacher['state']),EXPECTED['docente']))
    try:
        inv.command(t.node('controller'),'systemctl stop sdn-r1',True)
        r=inv.command(t.node('controller'),'python3 -c '+shlex.quote(PARTIAL),True)
        if r['code']:raise RuntimeError(r['stderr'])
        detail=json.loads(r['stdout']);t.check('partial_installation_cleaned',detail['remaining_individual_rules']==0,detail)
    finally:inv.command(t.node('controller'),'systemctl start sdn-r1',True)
    time.sleep(2)
    t.check('recovery_revalidates_permissions',t.access(t.call('h1','status',state=teacher['state']),EXPECTED['docente']))
    client_ip=inv.config()['network']['clients']['h1'];__import__('ipaddress').ip_address(client_ip)
    t.sql(f"UPDATE sessions SET expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE terminal_ip='{client_ip}' AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);")
    expired=t.call('h1','status',state=teacher['state'])
    t.check('expiry_removes_access',not expired['panel'] and t.access(expired,set()))
    t.check('final_no_live_sessions',t.sql("SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);")=='0')

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--ejecutar',action='store_true',required=True);p.parse_args()
    inv.OUT.mkdir(parents=True,exist_ok=True)
    tests=Tests()
    try:tests.preflight()
    except Exception:
        tests.close();raise
    try:main(tests)
    finally:
        try:
            tests.sql("UPDATE role_permissions p JOIN roles r ON r.id=p.role_id JOIN resources x ON x.id=p.resource_id SET p.allowed=1 WHERE r.code='docente' AND x.code='notas';")
            inv.command(tests.node('controller'),'systemctl start sdn-r1',True)
        finally:
            (inv.OUT/'pruebas_consistencia.json').write_text(json.dumps({'checks':tests.checks,'details':tests.details},indent=2),encoding='utf-8')
            tests.close()
