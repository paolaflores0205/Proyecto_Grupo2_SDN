"""Offline catalog checks; does not connect to VNRT or install flows."""
import importlib.util,pathlib,sys,types,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
import os
os.environ['SDN_TOPOLOGY']=str(pathlib.Path(__file__).with_name('topology.fixture.json'))
sys.path.insert(0,str(ROOT/'actualizacion-multitabla/source'))
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj);return obj
module('vnrt_flujos_https_paso3',ROOT/'despliegue-portable/source/portable_context.py')
legacy=module('vnrt_avz7_red',ROOT/'despliegue-portable/source/portable_flows.py')
exec((ROOT/'despliegue-portable/source/verified_flow_helpers.py.inc').read_text(encoding='utf-8'),legacy.__dict__)
import vnrt_mt_red as red

def actual(f):
    keys=('in_port','eth_src','eth_dst','eth_type','ip_proto','ipv4_src','ipv4_dst','tcp_src','tcp_dst','udp_src','udp_dst','metadata')
    r={'priority':f['priority'],'tableId':hex(int(f['table'])),'hardTimeoutSec':f['hard_timeout'],
       'match':{k:f[k] for k in keys if k in f},'instructions':{}}
    if f['actions']:r['instructions']['instruction_apply_actions']={'actions':f['actions']}
    if 'instruction_goto_table' in f:r['instructions']['instruction_goto_table']={'instruction_goto_table':f['instruction_goto_table']}
    if 'instruction_write_metadata' in f:r['instructions']['instruction_write_metadata']={'instruction_write_metadata':str(int(f['instruction_write_metadata'],0)),'instruction_write_metadata_mask':str((1<<64)-1)}
    return r

class Catalog(unittest.TestCase):
    def test_base(self):
        base=red.baseline();self.assertEqual(len(base),48)
        self.assertEqual({s:sum(f['switch']==red.DPID[s] for f in base) for s in red.DPID},{'sw1':19,'sw2':20,'sw3':9})
        self.assertEqual(len({f['name'] for f in base}),len(base))
        for f in base:self.assertTrue(red.matches(f,actual(f)),f['name'])
    def test_session(self):
        for c in ('h1','h2'):
            fs=red.session_rules(c,28,'a'*64,'docente',True)
            self.assertEqual(len(fs),4)
            self.assertEqual(sorted(int(f['table']) for f in fs),[10,10,30,30])
            for f in fs:self.assertTrue(red.matches(f,actual(f)))
    def test_r2(self):
        for c in ('h1','h2'):
            for code in ('notas','administracion'):
                fs=red.permissions(c,code,28,'a'*64,'docente',True)
                self.assertEqual(len(fs),4)
                for f in fs:self.assertTrue(red.matches(f,actual(f)))
    def test_metadata_separation(self):
        self.assertNotEqual(red.context('a'*64,'docente',True),red.context('b'*64,'docente',True))
        self.assertNotEqual(red.context('a'*64,'docente',True),red.context('a'*64,'docente',False))
    def test_mismatches(self):
        f=red.session_rules('h1',28,'a'*64,'docente',True)[0];r=actual(f)
        r['instructions']['instruction_goto_table']['instruction_goto_table']='30';self.assertFalse(red.matches(f,r))
        r=actual(f);r['tableId']='0x0';self.assertFalse(red.matches(f,r))

if __name__=='__main__':unittest.main()
