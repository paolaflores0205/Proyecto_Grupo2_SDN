"""Interactive client check. Never saves cookies, passwords or session identifiers."""
import argparse,getpass,http.cookiejar,json,re,ssl,time,urllib.error,urllib.request,urllib.parse
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--topology',default='/etc/sdn-g2/topology.json');p.add_argument('--trust',default='/etc/sdn-g2/trust.pem');a=p.parse_args()
    c=json.loads(Path(a.topology).read_text());context=ssl.create_default_context(cafile=a.trust)
    jar=http.cookiejar.CookieJar()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar),urllib.request.HTTPSHandler(context=context))
    portal='https://'+c['nodes']['controller']['ip']
    targets={'lms':'https://'+c['nodes']['h3']['ip'],'notas':'https://'+c['nodes']['h4']['ip'],'administracion':'https://'+c['nodes']['h4']['ip']+':8443'}
    matrix={'estudiante':{'lms'},'docente':{'lms','notas'},'administrativo':{'administracion'},'visitante':set()}
    def fetch(url,data=None):
        with opener.open(url,data=data,timeout=8) as r:return r.status,r.read().decode('utf8')
    def csrf(html):
        m=re.search(r'name=[\"\']csrf[\"\'][^>]*value=[\"\']([^\"\']+)',html)
        if not m:raise RuntimeError('Missing CSRF field; no credentials sent')
        return m.group(1)
    def probes(allowed,stage):
        good=True
        for name,url in targets.items():
            try:status,_=fetch(url);reachable=status==200;note=str(status)
            except urllib.error.HTTPError as e:reachable=False;note='HTTP '+str(e.code)
            except (OSError,urllib.error.URLError):reachable=False;note='no response within test timeout'
            passed=reachable==(name in allowed);good &= passed
            print(json.dumps({'stage':stage,'resource':name,'expected_access':name in allowed,'reachable':reachable,'check':passed,'observation':note}))
        return good
    # Start only with a terminal whose previous session has been closed/revoked.
    _,html=fetch(portal+'/');ok=probes(set(),'before-login')
    role=input('Role (estudiante/docente/administrativo/visitante): ').strip()
    assert role in matrix
    username=input('New deployment username: ').strip();password=getpass.getpass('Password (not logged): ')
    data=urllib.parse.urlencode({'username':username,'password':password,'csrf':csrf(html)}).encode()
    status,html=fetch(portal+'/login',data);password='';data=b''
    assert status==200 and '/logout' in html,'Login/panel not verified'
    time.sleep(2);ok=probes(matrix[role],'active-'+role) and ok
    fetch(portal+'/logout',urllib.parse.urlencode({'csrf':csrf(html)}).encode())
    time.sleep(3);ok=probes(set(),'after-logout') and ok
    print('SMOKE_PASS' if ok else 'SMOKE_FAIL')
    print('A timeout alone is NOT proof of a policy block. Also inspect OVS rules and validate each resource with an allowed role.')
    if not ok:raise SystemExit(1)
if __name__=='__main__':main()
