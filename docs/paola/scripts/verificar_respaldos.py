#!/usr/bin/env python3
"""Verifica ocho respaldos privados sin extraerlos ni mostrar su contenido."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def inspect_archive(path):
    checksum = path.with_name(path.name + '.sha256')
    expected = checksum.read_text(encoding='utf-8').split()[0]
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != expected:
        raise ValueError(f'SHA256 externo incorrecto: {path.name}')
    with tarfile.open(path, 'r:gz') as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise ValueError('Entradas duplicadas.')
        for m in members:
            p = PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir() or m.issym()):
                raise ValueError('Entrada no esperada.')
        info = json.load(tar.extractfile('metadata/inventory.json'))
        records = json.load(tar.extractfile('metadata/manifest.json'))
        if set(names) != {r['path'] for r in records} | {'metadata/manifest.json'}:
            raise ValueError('Contenido distinto del manifiesto.')
        for r in records:
            member = tar.getmember(r['path'])
            if r['kind'] == 'file':
                if not member.isfile():
                    raise ValueError('Tipo incorrecto.')
                with tar.extractfile(member) as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != r['sha256']:
                        raise ValueError('SHA256 interno incorrecto.')
            elif r['kind'] == 'symlink':
                if not member.issym() or member.linkname != r['target']:
                    raise ValueError('Enlace incorrecto.')
            elif not member.isdir():
                raise ValueError('Directorio incorrecto.')
        if info['node'] == 'controller':
            for required in ('metadata/sdn_g2.sql', 'metadata/mysql-app-users.sql',
                             'filesystem/opt/sdn-portal-paso4/vnrt_avz7_adapter.py',
                             'filesystem/etc/sdn-portal-paso4/config.json',
                             'filesystem/etc/sdn-admin-paso7/config.json',
                             'filesystem/opt/sdn-floodlight/floodlight.jar'):
                if required not in names or tar.getmember(required).size == 0:
                    raise ValueError(f'Falta componente esperado: {required}')
        if info['node'] in ('controller', 'h3', 'h4') and not info['quiesced']:
            raise ValueError('Respaldo sin pausa de servicios.')
    return info['node'], actual


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('folder', type=Path)
    a = ap.parse_args()
    found = {}
    for p in sorted(a.folder.glob('*.tar.gz')):
        node, digest = inspect_archive(p)
        if node in found:
            raise SystemExit('DETENIDO: más de un respaldo para un nodo; separar por campaña.')
        found[node] = (p.name, digest)
        print(f'OK {node}: integridad externa e interna correcta.')
    missing = set(('controller', 'sw1', 'sw2', 'sw3', 'h1', 'h2', 'h3', 'h4')) - set(found)
    if missing:
        raise SystemExit('FALTAN NODOS: ' + ', '.join(sorted(missing)))
    # Recibo privado: no convierte el respaldo en una imagen completa de VM.
    (a.folder / 'VERIFICACION_LOCAL.json').write_text(json.dumps(found, indent=2), encoding='utf-8')
    print('8/8 nodos verificados. Guardar una segunda copia privada. Restauración aún no ensayada.')


if __name__ == '__main__':
    main()
