"""Final R1/R2 flow design, with configurable addresses and OVS port numbers."""
import argparse,json,time
from vnrt_flujos_https_paso3 import C,DPID,HOSTS,ADJ,path,stored_names,api
P='g2-v7-'
SPEC={'lms':('h3',443),'notas':('h4',443),'administracion':('h4',8443)}
CLIENTS={HOSTS[n][3]:n for n in ('h1','h2')}
def flow(sw,name,priority,actions='',**match):
    return dict(switch=DPID[sw],name=P+name,table='0',priority=str(priority),active='true',
        idle_timeout='0',hard_timeout='0',actions=actions,**{k:str(v) for k,v in match.items()})
def baseline():
    result=[]
    for sw in DPID:
        result.append(flow(sw,'default-'+sw,50))
        for port in ADJ[sw].values():
            for typ in ('0x88cc','0x8942'):
                result.append(flow(sw,'discovery-'+sw+'-'+str(port)+'-'+typ,64000,
                    'output=controller',in_port=port,eth_type=typ))
    for name,(origin,port,mac,ip) in HOSTS.items():
        for sw in DPID:
            if name in ('h1','h2') and sw!='sw2':continue
            route=path(origin,sw);incoming=port if len(route)==1 else ADJ[sw][route[-2]]
            outputs=[int(p) for p in C['switches'][sw]['ports'] if int(p)!=incoming]
            actions=','.join('output='+str(p) for p in outputs)
            if sw==origin and name in ('h1','h2'):actions+=',output=controller'
            result.append(flow(sw,'arp-'+name+'-'+sw,300,actions,in_port=incoming,eth_src=mac,eth_type='0x0806'))
    cport=HOSTS['controller'][1];a=ADJ['sw1']['sw2'];s=ADJ['sw1']['sw3']
    up=ADJ['sw2']['sw1'];sup=ADJ['sw3']['sw1']
    h3p=HOSTS['h3'][1];h4p=HOSTS['h4'][1]
    result.append(flow('sw1','arp-access-transit-sw1',300,f'output={cport},output={s}',in_port=a,eth_type='0x0806'))
    result.append(flow('sw3','arp-access-transit-sw3',300,f'output={h4p},output={h3p}',in_port=sup,eth_type='0x0806'))
    for client in CLIENTS.values():
        sw,port,mac,ip=HOSTS[client]
        result.append(flow(sw,'dhcp-'+client+'-'+sw,400,'output='+str(up),
            in_port=port,eth_src=mac,eth_type='0x0800',ip_proto=17,udp_src=68,udp_dst=67))
        for source,target in ((client,'controller'),('controller',client)):
            origin,inp,smac,sip=HOSTS[source];end,out,dmac,dip=HOSTS[target];route=path(origin,end)
            for i,switch in enumerate(route):
                if switch=='sw1':continue
                incoming=inp if i==0 else ADJ[switch][route[i-1]]
                outgoing=out if i==len(route)-1 else ADJ[switch][route[i+1]]
                fields=dict(in_port=incoming,eth_src=smac,eth_dst=dmac,eth_type='0x0800',
                    ip_proto=6,ipv4_src=sip+'/32',ipv4_dst=dip+'/32')
                fields['tcp_dst' if target=='controller' else 'tcp_src']=443
                result.append(flow(switch,'portal-'+source+'-'+target+'-'+switch,400,'output='+str(outgoing),**fields))
    _,_,servermac,serverip=HOSTS['controller']
    for sw,inp,actions in [('sw1',cport,'output='+str(a)),('sw2',up,'output='+str(HOSTS['h1'][1])+',output='+str(HOSTS['h2'][1]))]:
        result.append(flow(sw,'dhcp-return-'+sw,400,actions,in_port=inp,eth_src=servermac,
            eth_type='0x0800',ipv4_src=serverip+'/32',ip_proto=17,udp_src=67,udp_dst=68))
    result.append(flow('sw1','dhcp-access-transit',400,'output='+str(cport),in_port=a,
        eth_type='0x0800',ip_proto=17,udp_src=68,udp_dst=67))
    result.append(flow('sw1','portal-access-transit',400,'output='+str(cport),in_port=a,eth_dst=servermac,
        eth_type='0x0800',ipv4_src=C['data_cidr'],ipv4_dst=serverip+'/32',ip_proto=6,tcp_dst=443))
    result.append(flow('sw1','portal-return-transit',400,'output='+str(a),in_port=cport,eth_src=servermac,
        eth_type='0x0800',ipv4_src=serverip+'/32',ipv4_dst=C['data_cidr'],ip_proto=6,tcp_src=443))
    for code,(server,port) in SPEC.items():
        _,_,mac,ip=HOSTS[server]
        result.append(flow('sw1','transit-'+code+'-ida',350,'output='+str(s),in_port=a,
            eth_dst=mac,eth_type='0x0800',ipv4_src=C['data_cidr'],ipv4_dst=ip+'/32',ip_proto=6,tcp_dst=port))
        result.append(flow('sw1','transit-'+code+'-retorno',350,'output='+str(a),in_port=s,
            eth_src=mac,eth_type='0x0800',ipv4_src=ip+'/32',ipv4_dst=C['data_cidr'],ip_proto=6,tcp_src=port))
    return result
def permissions(client,code,seconds,session_id):
    server,service=SPEC[code];sw,port,mac,ip=HOSTS[client];_,sport,smac,sip=HOSTS[server]
    suffix=session_id[:16]+'-'+client+'-'+code;result=[]
    for switch,name,inp,out,srcmac,dstmac,srcip,dstip,field in [
        ('sw2','ida',port,ADJ['sw2']['sw1'],mac,smac,ip,sip,'tcp_dst'),
        ('sw3','ida',ADJ['sw3']['sw1'],sport,mac,smac,ip,sip,'tcp_dst'),
        ('sw3','retorno',sport,ADJ['sw3']['sw1'],smac,mac,sip,ip,'tcp_src'),
        ('sw2','retorno',ADJ['sw2']['sw1'],port,smac,mac,sip,ip,'tcp_src')]:
        f=flow(switch,'grant-'+suffix+'-'+switch+'-'+name,500,'output='+str(out),
            in_port=inp,eth_src=srcmac,eth_dst=dstmac,eth_type='0x0800',
            ipv4_src=srcip+'/32',ipv4_dst=dstip+'/32',ip_proto=6,**{field:service})
        f['hard_timeout']=str(seconds);result.append(f)
    return result
