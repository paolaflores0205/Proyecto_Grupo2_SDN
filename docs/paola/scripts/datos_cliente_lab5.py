#!/usr/bin/env python3
"""Cambio reversible SOLO de ens4 en h1/h2: DHCP proyecto <-> IP estática Lab5."""
import argparse
import copy
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess


def run(*cmd):
    return subprocess.check_output(cmd, text=True)


def mgmt_state():
    addresses = json.loads(run('ip', '-j', '-4', 'address', 'show', 'ens3'))
    addr = [(r['ifname'], sorted((a['local'], a['prefixlen']) for a in r['addr_info'])) for r in addresses]
    routes = [r for r in json.loads(run('ip', '-j', '-4', 'route')) if r.get('dev') == 'ens3']
    return addr, routes


def main():
    import yaml
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--lab-static', action='store_true')
    group.add_argument('--restore', type=Path, help='Directorio exacto de respaldo que imprimió --lab-static.')
    a = ap.parse_args()
    node = socket.gethostname().split('.')[0]
    if os.geteuid() != 0 or node not in ('h1', 'h2'):
        ap.error('Solo sudo en h1 o h2.')
    if run('systemctl', 'is-active', 'systemd-networkd').strip() != 'active':
        ap.error('Requiere systemd-networkd activo.')
    if run('ip', '-j', 'link', 'show', 'ens4') == '':
        ap.error('No existe ens4.')
    os.umask(0o077)
    before = mgmt_state()
    candidates = []
    for file in Path('/etc/netplan').glob('*.yaml'):
        data = yaml.safe_load(file.read_text()) or {}
        if 'ens4' in data.get('network', {}).get('ethernets', {}):
            candidates.append((file, data))
    if len(candidates) != 1:
        ap.error('ens4 debe estar explícita en un único YAML. Revisar, no aplicar a ciegas.')
    file, data = candidates[0]
    current = file.read_bytes()
    if a.restore:
        folder = a.restore.resolve()
        if folder.parent != Path('/var/backups') or not folder.name.startswith('sdn-lab5-data-' + node + '-'):
            ap.error('Directorio de respaldo no válido para este nodo.')
        state = json.loads((folder / 'state.json').read_text())
        if state['node'] != node or state['file'] != str(file):
            ap.error('El respaldo no corresponde al archivo/nodo actual.')
        original = (folder / 'original.yaml').read_bytes()
        restored = yaml.safe_load(original)
        # No sobrescribir cambios de gestión hechos posteriormente por otra persona.
        left, right = copy.deepcopy(data), copy.deepcopy(restored)
        left['network']['ethernets'].pop('ens4')
        right['network']['ethernets'].pop('ens4')
        if left != right:
            ap.error('Cambió configuración fuera de ens4; revisar antes de restaurar.')
        replacement = original
    else:
        settings = data['network']['ethernets']['ens4']
        if any(k in settings for k in ('match', 'set-name', 'routes', 'gateway4', 'gateway6', 'nameservers')):
            ap.error('Configuración compleja en ens4; requiere revisión.')
        if settings.get('dhcp4') is not True:
            ap.error('ens4 no está en DHCP de proyecto; revisar, no cambiar otra configuración.')
        if data['network'].get('renderer', 'networkd') != 'networkd':
            ap.error('Renderer no esperado.')
        folder = Path('/var/backups') / ('sdn-lab5-data-' + node + '-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        folder.mkdir(mode=0o700)
        (folder / 'original.yaml').write_bytes(current)
        (folder / 'state.json').write_text(json.dumps({'node': node, 'file': str(file)}))
        settings['dhcp4'] = False
        settings.pop('dhcp4-overrides', None)
        settings.pop('dhcp-identifier', None)
        settings['addresses'] = ['10.0.0.' + ('1' if node == 'h1' else '2') + '/24']
        replacement = yaml.safe_dump(data, sort_keys=False).encode()
    try:
        file.write_bytes(replacement)
        file.chmod(0o600)
        run('netplan', 'generate')
        run('networkctl', 'reload')
        run('networkctl', 'reconfigure', 'ens4')
        if before != mgmt_state():
            raise RuntimeError('Cambió gestión; se intentará restaurar el YAML anterior.')
    except Exception:
        file.write_bytes(current)
        run('netplan', 'generate')
        run('networkctl', 'reload')
        run('networkctl', 'reconfigure', 'ens4')
        raise
    print('Configuración ens4 aplicada; gestión ens3 conservada. Verificar IP y una segunda sesión SSH.')
    if not a.restore:
        print('RESPALDO PARA VOLVER A DHCP:', folder)
    print('No se añadió gateway ni DNS al plano de datos.')


if __name__ == '__main__':
    main()
