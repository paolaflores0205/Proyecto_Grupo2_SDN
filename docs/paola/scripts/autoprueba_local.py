#!/usr/bin/env python3
"""Pruebas con datos artificiales: no usa SSH ni modifica nodos VNRT."""
import ast
import hashlib
import io
import json
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from verificar_respaldos import inspect_archive


def make_archive(folder, node):
    files = {
        'metadata/inventory.json': json.dumps({'node': node, 'quiesced': True,
                                               'timestamp_utc': 'synthetic-test'}).encode(),
        'filesystem/opt/sdn-test/ejemplo.py': b'print("synthetic")\n',
        'filesystem/etc/sdn-test/config.json': b'{"private":"SYNTHETIC_ONLY"}',
        'filesystem/opt/sdn-test/server.key': b'SYNTHETIC_PRIVATE_KEY_NOT_REAL',
    }
    if node == 'controller':
        for name in ('metadata/sdn_g2.sql', 'metadata/mysql-app-users.sql',
                     'filesystem/opt/sdn-portal-paso4/vnrt_avz7_adapter.py',
                     'filesystem/etc/sdn-portal-paso4/config.json',
                     'filesystem/etc/sdn-admin-paso7/config.json',
                     'filesystem/opt/sdn-floodlight/floodlight.jar'):
            files[name] = b'SYNTHETIC_ONLY'
    manifest = [{'path': name, 'kind': 'file', 'sha256': hashlib.sha256(data).hexdigest()}
                for name, data in files.items()]
    files['metadata/manifest.json'] = json.dumps(manifest).encode()
    path = folder / (node + '-synthetic.tar.gz')
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    path.with_name(path.name + '.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name)
    return path


def main():
    scripts = Path(__file__).resolve().parent
    for path in scripts.glob('*.py'):
        compile(path.read_text(encoding='utf-8'), str(path), 'exec')
    # Probar el parser SQL sin importar pwd (módulo exclusivo de Linux).
    tree = ast.parse((scripts / 'respaldar_nodo.py').read_text(encoding='utf-8'))
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'create_user_statement')
    namespace = {'re': re}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), '<sql-parser-test>', 'exec'), namespace)
    parse = namespace['create_user_statement']
    sql = "CREATE USER 'synthetic'@'127.0.0.1' IDENTIFIED BY 'NOT_A_REAL_SECRET'"
    assert parse((sql,)) == sql + ';'
    assert parse(('label', sql + ';')) == sql + ';'
    for bad in (None, (), ('label',), (sql, sql)):
        try:
            parse(bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Parser aceptó salida SQL ambigua o vacía.')
    with tempfile.TemporaryDirectory(prefix='sdn-synthetic-') as td:
        root = Path(td)
        backups = root / 'backups'
        backups.mkdir()
        for node in ('controller', 'sw1', 'sw2', 'sw3', 'h1', 'h2', 'h3', 'h4'):
            make_archive(backups, node)
        subprocess.run([sys.executable, str(scripts / 'verificar_respaldos.py'), str(backups)], check=True)
        exported = root / 'public-code'
        subprocess.run([sys.executable, str(scripts / 'exportar_codigo.py'), '--backups', str(backups),
                        '--out', str(exported)], check=True)
        assert list(exported.rglob('ejemplo.py')), 'No se exportó código permitido.'
        assert not list(exported.rglob('config.json')), 'Se exportó configuración privada.'
        assert not list(exported.rglob('*.key')), 'Se exportó una clave.'
        assert not list(exported.rglob('*.sql')), 'Se exportó SQL.'
        sample = next(backups.glob('h1-*.tar.gz'))
        checksum = sample.with_name(sample.name + '.sha256')
        original_checksum = checksum.read_text()
        checksum.write_text('0' * 64 + '  ' + sample.name)
        try:
            inspect_archive(sample)
        except ValueError:
            pass
        else:
            raise AssertionError('No se detectó checksum incorrecto.')
        checksum.write_text(original_checksum)
        # Alterar un contenido pero calcular un hash externo nuevo: debe fallar
        # igualmente el manifiesto interno.
        with tarfile.open(sample, 'r:gz') as tar:
            content = [(m.name, tar.extractfile(m).read()) for m in tar.getmembers()]
        with tarfile.open(sample, 'w:gz') as tar:
            for name, payload in content:
                if name.endswith('ejemplo.py'):
                    payload += b'# tampered\n'
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
        checksum.write_text(hashlib.sha256(sample.read_bytes()).hexdigest() + '  ' + sample.name)
        try:
            inspect_archive(sample)
        except ValueError:
            pass
        else:
            raise AssertionError('No se detectó alteración interna.')
    print('AUTOPRUEBA OK: sintaxis, parser SQL de una/dos columnas, 8 nodos artificiales, exportación selectiva y detección de alteración.')
    print('No verifica SSH, sudo, espacio real, mysqldump, pausa ni restauración de las VM.')


if __name__ == '__main__':
    main()
