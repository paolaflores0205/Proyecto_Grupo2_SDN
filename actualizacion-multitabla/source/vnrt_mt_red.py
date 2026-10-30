"""R1 shared LMS policy and R2 exact grants. Metadata is local to sw2."""
import argparse, hashlib, json, time
import vnrt_avz7_red as legacy

api=legacy.api; DPID=legacy.DPID; HOSTS=legacy.HOSTS; SPEC=legacy.SPEC; CLIENTS=legacy.CLIENTS
stored_names=legacy.stored_names; all_actual=legacy.all_actual; normal=legacy.normal
P='g2-mt-'; LMS=1<<62; ROLE={'estudiante':1,'docente':2,'administrativo':3,'visitante':4}
UP=legacy.ADJ['sw2']['sw1'];SUP=legacy.ADJ['sw3']['sw1']
DATA_CIDR=legacy.C['data_cidr']

def number(v):
    if isinstance(v,dict):v=v.get('value',v.get('portNumber',v))
    s=str(v).lower()
    while s.startswith('0x0x'):s=s[2:]
    return int(s,16) if s.startswith('0x') else int(s)

def flow(sw,name,table,priority,actions='',**fields):
    return dict(switch=DPID[sw],name=P+name,table=str(table),priority=str(priority),active='true',
                idle_timeout='0',hard_timeout='0',actions=actions,**{k:str(v) for k,v in fields.items()})

def baseline():
    result=[]
    for old in legacy.baseline():
        f=dict(old);f['name']=P+'base-'+old['name'][len(legacy.P):]
        if f['switch']==DPID['sw2'] and old['name']==legacy.P+'default-sw2':
            f['instruction_goto_table']='10'
        result.append(f)
    for table in (10,20,30):result.append(flow('sw2','miss-'+str(table),table,0))
    # A valid classifier supplies LMS eligibility. No client can supply metadata on the wire.
    for direction in (0,1):
        _,_,mac,ip=HOSTS['h3']
        fields={'metadata':hex(LMS|direction)+'/'+hex(LMS|1),'eth_type':'0x0800','ip_proto':6}
        fields.update({'eth_dst':mac,'ipv4_dst':ip+'/32','tcp_dst':443} if direction==0 else
                      {'eth_src':mac,'ipv4_src':ip+'/32','tcp_src':443})
        f=flow('sw2','lms-shared-sw2-'+str(direction),20,400,**fields);f['instruction_goto_table']='30';result.append(f)
    _,sport,smac,sip=HOSTS['h3']
    for direction in (0,1):
        fields=dict(in_port=SUP if direction==0 else sport,eth_type='0x0800',ip_proto=6)
        fields.update(dict(eth_dst=smac,ipv4_src=DATA_CIDR,ipv4_dst=sip+'/32',tcp_dst=443) if direction==0 else
                      dict(eth_src=smac,ipv4_src=sip+'/32',ipv4_dst=DATA_CIDR,tcp_src=443))
        result.append(flow('sw3','lms-shared-sw3-'+str(direction),0,350,'output='+str(sport if direction==0 else SUP),**fields))
    return result

def context(session_id,role,lms):
    tag=int(hashlib.sha256(session_id.encode()).hexdigest()[:12],16)&((1<<47)-1)
    return (LMS if lms else 0)|(ROLE[role]<<48)|(tag<<1)

def session_rules(client,seconds,sid,role,lms):
    _,port,mac,ip=HOSTS[client];ctx=context(sid,role,lms);result=[]
    for direction in (0,1):
        fields={'in_port':port if direction==0 else UP,'eth_type':'0x0800'}
        fields.update({'eth_src':mac,'ipv4_src':ip+'/32'} if direction==0 else {'eth_dst':mac,'ipv4_dst':ip+'/32'})
        f=flow('sw2','session-'+sid[:16]+'-'+client+'-class-'+str(direction),10,500,**fields)
        f.update(instruction_write_metadata=hex(ctx|direction),instruction_goto_table='20',hard_timeout=str(seconds));result.append(f)
        f=flow('sw2','session-'+sid[:16]+'-'+client+'-route-'+str(direction),30,500,
               'output='+str(UP if direction==0 else port),metadata=hex(ctx|direction))
        f['hard_timeout']=str(seconds);result.append(f)
    return result

def permissions(client,code,seconds,sid,role,lms):
    if code=='lms':return []
    result=[];ctx=context(sid,role,lms)
    for old in legacy.permissions(client,code,seconds,sid):
        f=dict(old);f['name']=P+old['name'][len(legacy.P):]
        if f['switch']==DPID['sw2']:
            f['table']='20';f['actions']='';f['metadata']=hex(ctx|(1 if '-retorno' in f['name'] else 0))
            f['instruction_goto_table']='30'
        result.append(f)
    return result

def push(f):
    reply=api('/wm/staticflowpusher/json','POST',f)
    if 'pushed' not in str(reply).lower():raise RuntimeError('Flow rejected')

def remove(names):
    for name in names:api('/wm/staticflowpusher/json','DELETE',{'name':name})

def metadata(v):
    if isinstance(v,dict):
        value=v.get('value',v.get('metadata',v.get('rawValue')));mask=v.get('mask')
        if value is None:raise ValueError('Unknown metadata representation')
        return number(value),number(mask) if mask is not None else (1<<64)-1
    parts=str(v).split('/')
    return number(parts[0]),number(parts[1]) if len(parts)>1 else (1<<64)-1

def matches(f,r):
    if number(r['priority'])!=int(f['priority']) or number(r.get('tableId',r.get('table_id',0)))!=int(f['table']):return False
    keys=('in_port','eth_src','eth_dst','eth_type','ip_proto','ipv4_src','ipv4_dst','tcp_src','tcp_dst','udp_src','udp_dst','metadata')
    expected={k for k in keys if k in f};observed=r.get('match',{})
    if set(observed)!=expected:return False
    for k in expected:
        if k=='metadata':
            if metadata(f[k])!=metadata(observed[k]):return False
        elif normal(k,f[k])!=normal(k,observed[k]):return False
    ins=r.get('instructions',{})
    actual=ins.get('instruction_apply_actions',{}).get('actions','')
    if sorted(str(actual).lower().split(','))!=sorted(f['actions'].lower().split(',')):return False
    actualgo=ins.get('instruction_goto_table',{}).get('instruction_goto_table')
    if ('instruction_goto_table' in f)!=(actualgo is not None):return False
    if actualgo is not None and number(actualgo)!=int(f['instruction_goto_table']):return False
    actualmd=ins.get('instruction_write_metadata',{})
    if 'instruction_write_metadata' in f:
        if number(actualmd.get('instruction_write_metadata',-1))!=number(f['instruction_write_metadata']):return False
        if number(actualmd.get('instruction_write_metadata_mask',0))&((1<<64)-1)!=(1<<64)-1:return False
    elif actualmd:return False
    timeout=number(r.get('hardTimeoutSec',0))
    return (0<timeout<=30) if int(f['hard_timeout']) else timeout==0

def verify_actual(wanted,timeout=5):
    end=time.monotonic()+timeout
    while True:
        rows=all_actual();missing=[f['name'] for f in wanted if not any(matches(f,r) for r in rows[f['switch']])]
        if not missing:return rows
        if time.monotonic()>end:raise RuntimeError('Dataplane mismatch: '+','.join(missing[:4]))
        time.sleep(.2)

def bootstrap():
    # Caller stops the old adapter and confirms no live sessions before this cutover.
    until=time.monotonic()+55
    while True:
        try:
            if {r['switchDPID'] for r in api('/wm/core/controller/switches/json')}==set(DPID.values()):
                stored_names();break
        except Exception:pass
        if time.monotonic()>until:raise RuntimeError('Controller API or switches not ready for bootstrap')
        time.sleep(1)
    wanted=baseline();current=stored_names()
    # Old deny remains during removal; unknown traffic stays restricted.
    remove([n for n in current if n.startswith((P,legacy.P,'g2-p2-','g2-p3-','g2-p4-','g2-p5-','g2-p6-')) and 'default-' not in n])
    for f in wanted:
        if f['table']!='0':push(f)
    for f in wanted:
        if f['table']=='0' and f['name']!=P+'base-default-sw2':push(f)
    # Remove only project-owned old defaults after the restrictive new stages exist.
    remove([n for n in stored_names() if n.startswith((legacy.P,P,'g2-p2-','g2-p3-','g2-p4-','g2-p5-','g2-p6-')) and 'default-' in n])
    for f in wanted:
        if 'default-' in f['name']:push(f)
    verify_actual(wanted,15)
    print(json.dumps({'baseline':len(wanted),'tables_sw2':[0,10,20,30],'metadata':True,'r2_per_permission':4}))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['bootstrap','verify','show']);action=parser.parse_args().action
    if action=='bootstrap':bootstrap()
    elif action=='verify':verify_actual(baseline());print('MULTITABLE_BASE_VERIFIED')
    else:print(json.dumps(baseline(),indent=2))
