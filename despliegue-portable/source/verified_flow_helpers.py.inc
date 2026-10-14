def push(f):
    r = api('/wm/staticflowpusher/json', 'POST', f)
    if 'pushed' not in str(r).lower():
        raise RuntimeError('Controller rejected flow')

def remove(names):
    for name in names:
        api('/wm/staticflowpusher/json', 'DELETE', {'name': name})

def all_actual():
    result = {}
    for sw, dpid in DPID.items():
        raw = api('/wm/core/switch/' + dpid + '/flow/json')
        rows = []

        def visit(value):
            if isinstance(value, dict):
                if 'match' in value and 'priority' in value:
                    rows.append(value)
                else:
                    for item in value.values():
                        visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        visit(raw)
        result[dpid] = rows
    return result

def normal(key, value):
    if isinstance(value, dict):
        value = value.get('portNumber', value.get('value', value))
    text = str(value).lower()
    while text.startswith('0x0x'):
        text = text[2:]
    if key in ('eth_type', 'ip_proto', 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst', 'in_port'):
        try:
            return int(text, 16) if text.startswith('0x') else int(text)
        except ValueError:
            return text
    if key.startswith('ipv4_'):
        import ipaddress
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return text
    return text

def actual_contains(f, rows):
    keys = ('in_port', 'eth_src', 'eth_dst', 'eth_type', 'ip_proto', 'ipv4_src', 'ipv4_dst', 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst')
    for r in rows:
        if normal('in_port', r['priority']) != int(f['priority']):
            continue
        if normal('in_port', r.get('tableId', r.get('table_id', 0))) != 0:
            continue
        match = r['match']
        if set(match) != {k for k in keys if k in f}:
            continue
        if all((k in match and normal(k, match[k]) == normal(k, f[k]) for k in keys if k in f)):
            actual = r.get('instructions', {}).get('instruction_apply_actions', {}).get('actions', '')
            if sorted(str(actual).lower().split(',')) != sorted(f['actions'].lower().split(',')) and (not (not f['actions'] and (not actual))):
                continue
            timeout = normal('in_port', r.get('hardTimeoutSec', 0))
            if f['name'].startswith(P + 'grant-') and (not (isinstance(timeout, int) and 0 < timeout <= 30)):
                continue
            return True
    return False

def verify_actual(wanted, timeout=4):
    until = time.monotonic() + timeout
    while True:
        observed = all_actual()
        missing = [f['name'] for f in wanted if not actual_contains(f, observed[f['switch']])]
        if not missing:
            return observed
        if time.monotonic() > until:
            raise RuntimeError('Actual OVS rules missing: ' + ','.join(missing[:6]))
        time.sleep(0.2)

def bootstrap():
    until = time.monotonic() + 55
    while True:
        try:
            if {s['switchDPID'] for s in api('/wm/core/controller/switches/json')} == set(DPID.values()):
                break
        except Exception:
            pass
        if time.monotonic() > until:
            raise RuntimeError('Switches unavailable')
        time.sleep(1)
    wanted = baseline()
    defaults = {f['name'] for f in wanted if f['name'].startswith(P + 'default-')}
    remove([n for n in stored_names() if n in defaults])
    for f in wanted:
        if f['name'] in defaults:
            push(f)
    verify_actual([f for f in wanted if f['name'] in defaults], timeout=15)
    remove([n for n in stored_names() if n.startswith(('g2-p2-', 'g2-p3-', 'g2-p4-', 'g2-p5-', 'g2-p6-')) or (n.startswith(P) and n not in defaults)])
    for f in wanted:
        if f['name'] not in defaults:
            push(f)
    verify_actual(wanted, timeout=15)
    print(json.dumps({'baseline': len(wanted), 'individual_per_permission': 4, 'metadata': False}))
