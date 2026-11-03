"""Root post-start observation, confined to two data neighbors."""
import json,subprocess
from pathlib import Path
c=json.loads(Path('/etc/sdn-g2/topology.json').read_text());n=c['nodes']['controller'];iface=n['data_interface']
actual=json.loads(subprocess.check_output(['ip','-j','-4','address','show',iface]))
assert any(a['local']==n['ip'] for row in actual for a in row['addr_info'])
for h in ('h1','h2'):
    ip=c['nodes'][h]['ip']
    subprocess.run(['ip','neigh','del',ip,'dev',iface],capture_output=True)
    subprocess.run(['ping','-c','1','-W','1','-I',iface,ip],capture_output=True)
print('Data ARP discovery requested; management unchanged')
