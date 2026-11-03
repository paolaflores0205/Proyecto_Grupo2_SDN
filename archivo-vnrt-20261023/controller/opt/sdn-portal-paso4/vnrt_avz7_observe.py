"""Relearn the two reserved terminals after Floodlight restart; data NIC only."""
import json,subprocess

addresses=json.loads(subprocess.check_output(['ip','-j','-4','address','show','ens4']))
if not any(a['local']=='192.0.2.10' for row in addresses for a in row['addr_info']):
    raise SystemExit('Expected data interface is unavailable')
for ip in ('192.0.2.1','192.0.2.2'):
    # Never flush an interface or a route: replace only these data-neighbor records.
    subprocess.run(['ip','neigh','del',ip,'dev','ens4'],capture_output=True)
    # ICMP is denied by the baseline, but its ARP resolution is permitted and
    # the terminal's reply is copied to DeviceManager by the access switch.
    subprocess.run(['ping','-c','1','-W','1','-I','ens4',ip],capture_output=True)
print('Reserved terminal ARP discovery requested; no permissions granted')
