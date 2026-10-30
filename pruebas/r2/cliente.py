"""Remote client test. Credentials and cookies only on stdin/stdout to the orchestrator."""
import http.cookiejar,json,re,ssl,sys,urllib.request,urllib.parse,urllib.error
p=json.load(sys.stdin);jar=http.cookiejar.CookieJar();net=p['network'];url=net['portal_url']
for c in p.get('state',{}).get('cookies',[]):
    jar.set_cookie(http.cookiejar.Cookie(0,c['name'],c['value'],None,False,c['domain'],False,False,c['path'],True,True,None,True,None,None,{},False))
ctx=ssl.create_default_context(cafile=net['portal_ca'])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
def web(path,data=None):
    req=urllib.request.Request(url+path,data=None if data is None else urllib.parse.urlencode(data).encode())
    try:
        with opener.open(req,timeout=20) as r:return r.status,r.read().decode(),r.url
    except urllib.error.HTTPError as r:return r.code,r.read().decode(),r.url
def csrf(html):
    m=re.search(r'name="csrf" value="([^"]+)"',html);return m.group(1) if m else ''
def resources():
    result={}
    for code,resource in net['resources'].items():
        ip,port,cert=resource['ip'],resource['port'],resource['ca']
        probe=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cert)))
        try:
            with probe.open('https://'+ip+':'+str(port)+'/health',timeout=2) as r:
                body=json.load(r);result[code]=r.status if body.get('status')=='ok' else -1
        except (urllib.error.URLError,TimeoutError):result[code]=0
    return result
mode=p['mode']
if mode=='login':
    _,html,_=web('/');a=p['account'];code,html,location=web('/login',{'csrf':csrf(html),'username':a['username'],'password':a['password'],'role':'docente','terminal_ip':'192.0.2.250'})
    result={'code':code,'panel':location==url+'/panel','role_match':('id="verified-role">'+p['label']+'</strong>') in html,
        'access':resources(),'state':{'cookies':[{'name':c.name,'value':c.value,'domain':c.domain,'path':c.path} for c in jar],'csrf':csrf(html)}}
elif mode=='logout':
    code,_,location=web('/logout',{'csrf':p['state']['csrf']});result={'logged_out':location==url+'/','code':code,'access':resources()}
elif mode=='status':
    code,_,location=web('/panel');result={'panel':location==url+'/panel','code':code,'access':resources()}
elif mode=='invalid':
    _,html,_=web('/');code,_,_=web('/login',{'csrf':csrf(html),'username':'docente_demo','password':'invalid-avz7-test'});result={'rejected':code==401,'access':resources()}
else:
    code,_,_=web('/');healthcode,body,_=web('/health');result={'portal':code==200,'health_code':healthcode,'health':json.loads(body) if healthcode==200 else {},'access':resources()}
print(json.dumps(result))
