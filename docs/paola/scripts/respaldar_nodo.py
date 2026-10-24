#!/usr/bin/env python3
"""Respaldo PRIVADO de un nodo VNRT. Linux, root; nunca restaura ni limpia.

El modo --quiesce detiene servicios sdn-* del nodo y los deja detenidos.
No cambia Netplan, controladores OVS, flujos, enabled/masked ni MySQL.
"""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile

NODES = ('controller', 'sw1', 'sw2', 'sw3', 'h1', 'h2', 'h3', 'h4')


def capture(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=40)
    return {'command': args, 'returncode': p.returncode,
            'stdout': p.stdout, 'stderr': p.stderr}


def discover(project_only=False):
    paths = [Path(p) for p in (
        '/etc/netplan', '/etc/sdn-g2', '/etc/sdn-portal-paso4',
        '/etc/sdn-admin-paso7', '/etc/kea', '/etc/openvswitch',
        '/etc/mysql', '/var/lib/sdn-g2', '/var/lib/sdn-floodlight',
        '/var/lib/kea', '/etc/hosts', '/etc/hostname',
        '/etc/environment', '/etc/default/openvswitch-switch',
        '/etc/default/kea-dhcp4-server', '/etc/systemd/network')]
    for parent, pattern in (
        ('/opt', 'sdn-*'), ('/etc/systemd/system', 'sdn-*'),
        ('/etc/systemd/system', 'kea-dhcp4-server.service'),
        ('/etc/systemd/system', 'kea-dhcp4-server.service.d'),
        ('/var/backups', 'sdn-*'), ('/home/ubuntu', 'medir_r1*.py'),
        ('/home/ubuntu', 'evidencias-r1*'), ('/home/ubuntu', 'vnrt_avz7*'),
        ('/home/ubuntu', 'sdn-r1r2')):
        paths.extend(Path(parent).glob(pattern))
    if not project_only:
        for parent, pattern in (('/root', 'floodlight*'), ('/root', 'v1.2.zip'),
                                ('/home/ubuntu', 'floodlight*'), ('/home/ubuntu', 'v1.2.zip')):
            paths.extend(Path(parent).glob(pattern))
    # No se copia ~/.ssh ni .bash_history. Se preservan perfiles concretos
    # porque pueden contener la ruta Java usada por el laboratorio previo.
    paths.extend(Path(p) for p in ('/root/.bashrc', '/home/ubuntu/.bashrc'))
    result = []
    for p in sorted(set(paths), key=lambda x: (len(x.parts), str(x))):
        if not (p.exists() or p.is_symlink()):
            continue
        if not any(p == q or q in p.parents for q in result):
            result.append(p)
    return result


def entries(paths):
    for root in paths:
        yield root
        if root.is_dir() and not root.is_symlink():
            for base, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = sorted(d for d in dirs if d != '__pycache__')
                for name in sorted(dirs + files):
                    p = Path(base) / name
                    if p.suffix not in ('.pyc', '.pyo'):
                        yield p


def inventory(node, units):
    commands = {
        'addresses': ['ip', '-j', 'address'], 'routes': ['ip', '-j', 'route'],
        'os': ['cat', '/etc/os-release'], 'packages': ['dpkg-query', '-W'],
        'accounts': ['getent', 'passwd', 'ubuntu', 'sdnportal'],
        'groups': ['getent', 'group', 'ubuntu', 'sdnportal'],
        'disk': ['df', '-h', '/'], 'memory': ['free', '-h'],
        'listeners': ['ss', '-lntup'],
        'all_unit_files': ['systemctl', 'list-unit-files', '--no-pager'],
    }
    if node == 'controller':
        commands.update(java=['java', '-version'],
                        java_path=['readlink', '-f', '/usr/bin/java'])
    data = {'node': node, 'hostname': socket.gethostname(),
            'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'units_before': {}, 'commands': {}}
    for name, cmd in commands.items():
        if shutil.which(cmd[0]):
            data['commands'][name] = capture(cmd)
    for u in units:
        data['units_before'][u] = {
            'active': capture(['systemctl', 'is-active', u])['stdout'].strip(),
            'enabled': capture(['systemctl', 'is-enabled', u])['stdout'].strip(),
            'definition': capture(['systemctl', 'cat', u]),
        }
    if node.startswith('sw'):
        for name, cmd in {
            'ovs_show': ['ovs-vsctl', 'show'],
            'ovs_bridge': ['ovs-vsctl', 'list', 'Bridge', node],
            'ovs_interfaces': ['ovs-vsctl', 'list', 'Interface'],
            'ovs_controller': ['ovs-vsctl', 'get-controller', node],
            'ovs_ports': ['ovs-ofctl', '-O', 'OpenFlow13', 'show', node],
            'ovs_flows': ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', node],
            'ovs_groups': ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-groups', node],
            'ovs_meters': ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-meters', node],
        }.items():
            data['commands'][name] = capture(cmd)
    return data


def create_user_statement(row):
    # MySQL devuelve una columna; otras variantes pueden añadir una etiqueta.
    # Seleccionar la sentencia por su contenido, sin imprimir hashes/secretos.
    matches = [value for value in (row or ())
               if isinstance(value, str) and re.match(r'^\s*CREATE\s+USER\b', value, re.I)]
    if len(matches) != 1:
        raise RuntimeError('SHOW CREATE USER no devolvió una sentencia única; revisar compatibilidad SQL sin publicar su contenido.')
    return matches[0].rstrip().rstrip(';') + ';'


def mysql_backup(temp):
    import pymysql
    conn = pymysql.connect(unix_socket='/var/run/mysqld/mysqld.sock', user='root')
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='sdn_g2'")
        if cur.fetchone()[0] != 1:
            raise RuntimeError('No existe sdn_g2: detenerse y revisar, no generar respaldo incompleto.')
        users = {'sdn_portal', 'sdn_dti'}
        for config in ('/etc/sdn-portal-paso4/config.json', '/etc/sdn-admin-paso7/config.json'):
            value = json.loads(Path(config).read_text())['db_user']
            if not re.fullmatch(r'[A-Za-z0-9_]+', value):
                raise RuntimeError('Nombre de cuenta SQL inesperado.')
            users.add(value)
        cur.execute('SELECT User,Host FROM mysql.user WHERE User IN (' +
                    ','.join(['%s'] * len(users)) + ')', tuple(sorted(users)))
        found = cur.fetchall()
        if not found:
            raise RuntimeError('No se encontraron cuentas SQL de la aplicación.')
        statements = ['-- PRIVADO: cuentas SQL y hashes. Importar solo en instancia revisada.']
        for user, host in found:
            cur.execute('SHOW CREATE USER %s@%s', (user, host))
            statements.append(create_user_statement(cur.fetchone()))
            cur.execute('SHOW GRANTS FOR %s@%s', (user, host))
            statements.extend(row[0] + ';' for row in cur.fetchall())
        (temp / 'mysql-app-users.sql').write_text('\n'.join(statements) + '\n')
    conn.close()
    with (temp / 'sdn_g2.sql').open('wb') as out:
        p = subprocess.run(['mysqldump', '--protocol=socket', '--single-transaction',
                            '--routines', '--events', '--triggers', '--hex-blob',
                            '--no-tablespaces', '--set-gtid-purged=OFF',
                            '--databases', 'sdn_g2'], stdout=out, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError('Falló mysqldump; no hay respaldo válido. Revisar MySQL sin publicar secretos.')


def add_bytes(tar, name, payload):
    ti = tarfile.TarInfo(name)
    ti.size = len(payload)
    ti.mode = 0o600
    tar.addfile(ti, io.BytesIO(payload))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--node', required=True, choices=NODES)
    ap.add_argument('--quiesce', action='store_true', help='Detener servicios sdn-* y dejarlos detenidos.')
    ap.add_argument('--project-only', action='store_true',
                    help='Excluir copias históricas Floodlight de /root y /home/ubuntu; conservar instalación activa /opt y sdn-r1r2.')
    ap.add_argument('--out', default='/home/ubuntu/respaldos-vnrt-20261024')
    args = ap.parse_args()
    if os.geteuid() != 0 or socket.gethostname().split('.')[0] != args.node:
        ap.error('Ejecutar con sudo en el nodo correcto, comprobando hostname.')
    os.umask(0o077)
    dest = Path(args.out).resolve()
    if dest == Path('/') or not str(dest).startswith('/home/ubuntu/'):
        ap.error('La salida debe estar debajo de /home/ubuntu/.')
    paths = discover(project_only=args.project_only)
    for p in paths:
        if p == dest or p in dest.parents:
            ap.error('La salida no puede estar dentro de una ruta que se respalda.')
    all_entries = list(entries(paths))
    total = sum(p.lstat().st_size for p in all_entries if stat.S_ISREG(p.lstat().st_mode))
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    owner = pwd.getpwnam('ubuntu')
    if dest.is_symlink():
        ap.error('No se acepta salida simbólica.')
    dest.chmod(0o700)
    os.chown(dest, owner.pw_uid, owner.pw_gid)
    # Cota conservadora: datos sin comprimir, margen SQL y 128 MiB libres.
    sql_budget = 0
    if args.node == 'controller':
        size = subprocess.run(['mysql', '--protocol=socket', '--batch', '--skip-column-names',
                               '-e', "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='sdn_g2'"],
                              capture_output=True, text=True)
        if size.returncode != 0:
            raise SystemExit('DETENIDO: MySQL no responde; no se ha detenido ningún servicio.')
        # Margen para dump SQL temporal y su copia comprimida; no es cota matemática.
        sql_budget = max(64 * 1024**2, 4 * int(size.stdout.strip()))
    if shutil.disk_usage(dest).free < total + sql_budget + 192 * 1024**2:
        raise SystemExit('DETENIDO: espacio insuficiente para respaldo local conservador. '
                         'No borrar el proyecto. Usar snapshot/exportación VNRT o revisar traslado externo.')
    units = sorted(p.name for p in Path('/etc/systemd/system').glob('sdn-*.service') if p.is_file())
    info = inventory(args.node, units)
    info['backup_scope'] = 'installed_project_without_historical_floodlight' if args.project_only else 'project_and_historical_floodlight'
    checkpoint_tag = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    checkpoint = dest / f'{args.node}-{checkpoint_tag}-inventario-previo.json'
    checkpoint.write_text(json.dumps(info, indent=2))
    checkpoint.chmod(0o600)
    os.chown(checkpoint, owner.pw_uid, owner.pw_gid)
    if args.node in ('controller', 'h3', 'h4') and not args.quiesce:
        ap.error('Para estos nodos usar --quiesce después de finalizar las pruebas/sesiones.')
    if args.quiesce and units:
        front = [u for u in ('sdn-portal.service', 'sdn-admin.service', 'sdn-r1.service') if u in units]
        order = front + [u for u in units if u not in front]
        subprocess.run(['systemctl', 'stop', *order], check=True)
        if any(capture(['systemctl', 'is-active', u])['stdout'].strip() == 'active' for u in units):
            raise SystemExit('DETENIDO: un servicio sigue activo. Los demás pueden estar detenidos.')
    info['quiesced'] = bool(args.quiesce)
    tag = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    final = dest / f'{args.node}-{tag}.tar.gz'
    partial = final.with_suffix('.gz.partial')
    # Es temporal de metadatos/SQL, no una segunda copia de /opt.
    with tempfile.TemporaryDirectory(prefix='sdn-backup-', dir='/var/tmp') as td:
        temp = Path(td)
        if args.node == 'controller':
            mysql_backup(temp)
        manifest = []
        with tarfile.open(partial, 'w:gz', dereference=False) as tar:
            for p in all_entries:
                st = p.lstat()
                if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                    continue  # sockets, PID y dispositivos no son restaurables como archivos
                name = 'filesystem/' + str(p).lstrip('/')
                record = {'path': name, 'uid': st.st_uid, 'gid': st.st_gid,
                          'mode': oct(stat.S_IMODE(st.st_mode))}
                if stat.S_ISREG(st.st_mode):
                    with p.open('rb') as stream:
                        record['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
                    record['kind'] = 'file'
                elif stat.S_ISLNK(st.st_mode):
                    record.update(kind='symlink', target=os.readlink(p))
                else:
                    record['kind'] = 'directory'
                tar.add(p, arcname=name, recursive=False)
                manifest.append(record)
            payloads = {'metadata/inventory.json': json.dumps(info, indent=2).encode()}
            for p in temp.iterdir():
                payloads['metadata/' + p.name] = p.read_bytes()
            for name, data in payloads.items():
                add_bytes(tar, name, data)
                manifest.append({'path': name, 'kind': 'file',
                                 'sha256': hashlib.sha256(data).hexdigest()})
            add_bytes(tar, 'metadata/manifest.json', json.dumps(manifest, indent=2).encode())
    # Lee todo el archivo y contrasta sus hashes antes de declararlo válido.
    with tarfile.open(partial, 'r:gz') as tar:
        for r in manifest:
            if r['kind'] == 'file':
                with tar.extractfile(r['path']) as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != r['sha256']:
                        raise RuntimeError('Falló verificación interna; conservar originales.')
    partial.rename(final)
    with final.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    checksum = final.with_name(final.name + '.sha256')
    checksum.write_text(f'{digest}  {final.name}\n')
    for p in (final, checksum):
        p.chmod(0o600)
        os.chown(p, owner.pw_uid, owner.pw_gid)
    print('RESPALDO PRIVADO:', final)
    print('SHA256:', digest)
    print('Verificación interna correcta. Copiar archivo y .sha256 fuera del slice.')
    if args.quiesce:
        print('Los servicios sdn-* quedaron DETENIDOS; no se deshabilitaron. No reiniciar el nodo antes de la guía de pausa.')


if __name__ == '__main__':
    main()
