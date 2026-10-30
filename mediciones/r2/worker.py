"""Persistent SSH worker. No credentials, cookies or tokens are returned."""
import sys,json,time,ssl,http.client,http.cookiejar,urllib.request,urllib.parse,urllib.error,re,socket
cfg=json.loads(sys.stdin.readline()); mode=cfg['mode'];net=cfg['network']
if mode=='probe':
 contexts={name:ssl.create_default_context(cafile=net['resources'][name]['ca']) for name in ('lms','notas')}
 def handle(p):
  name=p['resource'];ip=net['resources'][name]['ip']
  start=time.perf_counter();c=http.client.HTTPSConnection(ip,net['resources'][name]['port'],context=contexts[name],timeout=cfg['timeout'],source_address=(cfg['client_ip'],0))
  try:
   c.request('GET','/health',headers={'Connection':'close','Cache-Control':'no-cache'})
   r=c.getresponse();body=json.loads(r.read(4096));result={'status':r.status,'useful':r.status==200 and body.get('status')=='ok','error':None}
  except Exception as e:result={'status':0,'useful':False,'error':type(e).__name__}
  finally:c.close()
  result['request_ms']=(time.perf_counter()-start)*1000
  return result
else:
 raw=json.load(open(net['dti_accounts_path']))
 if isinstance(raw,list):raw=raw[0]
 if 'account' in raw:raw=raw['account']
 account={'username':raw.get('username',raw.get('usuario')),'password':raw.get('password',raw.get('contraseña'))}
 if not all(account.values()):raise RuntimeError('Unrecognized test account fields: '+','.join(raw.keys()))
 jar=http.cookiejar.CookieJar();url=net['dti_url']
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=net['dti_ca'])),urllib.request.HTTPCookieProcessor(jar))
 csrf_value=None
 def web(path,data=None):
  global csrf_value
  request=urllib.request.Request(url+path,data=None if data is None else urllib.parse.urlencode(data).encode())
  try:
   with opener.open(request,timeout=20) as r:status,body,location=r.status,r.read().decode(),r.url
  except urllib.error.HTTPError as r:status,body,location=r.code,r.read().decode(),r.url
  found=re.search(r'name="csrf" value="([^"]+)"',body)
  if found:csrf_value=found.group(1)
  return {'status':status,'dashboard':location==url+'/dashboard','pending':'sincronización pendiente' in body}
 web('/');login=web('/login',{'csrf':csrf_value,**account});account=None;raw=None
 if login['status']!=200 or not login['dashboard']:raise RuntimeError('DTI test login did not succeed: '+str(login['status']))
 def handle(p):
  if p.get('operation')=='logout':return web('/logout',{'csrf':csrf_value})
  return web('/policy',{'csrf':csrf_value,'role_id':cfg['role_id'],'resource_id':cfg['resource_id'],'allowed':p['allowed'],'expected':p['expected']})
print(json.dumps({'ready':True,'mode':mode}),flush=True)
for line in sys.stdin:
 try:
  p=json.loads(line)
  if p.get('operation')=='close':break
  print(json.dumps(handle(p)),flush=True)
 except Exception as e:print(json.dumps({'worker_error':type(e).__name__}),flush=True)
