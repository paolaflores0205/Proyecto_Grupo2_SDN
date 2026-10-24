#!/usr/bin/env python3
"""Extrae solo código de respaldos verificados a una carpeta NUEVA revisable.

No hace git add/commit/push. No exporta SQL, claves, config.json ni logs.
El código puede contener secretos incrustados: revisión humana obligatoria.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import tarfile
from verificar_respaldos import inspect_archive


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--backups', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    if a.out.exists():
        ap.error('La salida debe ser nueva; no sobrescribir código de compañeros.')
    archives = sorted(a.backups.glob('*.tar.gz'))
    checked = [(p, *inspect_archive(p)) for p in archives]
    if len(checked) != 8 or {node for _, node, _ in checked} != {'controller', 'sw1', 'sw2', 'sw3', 'h1', 'h2', 'h3', 'h4'}:
        ap.error('Se necesitan los ocho respaldos verificados.')
    a.out.mkdir(parents=True)
    records = []
    for archive, node, digest in checked:
        with tarfile.open(archive, 'r:gz') as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                p = PurePosixPath(member.name)
                under_opt = (len(p.parts) >= 4 and p.parts[:2] == ('filesystem', 'opt')
                             and p.parts[2].startswith('sdn-'))
                client_script = (p.parts[:3] == ('filesystem', 'home', 'ubuntu')
                                 and p.name.startswith('medir_r1') and len(p.parts) == 4)
                smoke = member.name == 'filesystem/etc/sdn-g2/smoke_test.py'
                code = p.suffix in {'.py', '.html', '.css', '.inc'}
                if not (code and (under_opt or client_script or smoke)):
                    continue
                if member.size > 5 * 1024**2:
                    raise SystemExit('Archivo de código inusualmente grande: revisar manualmente.')
                target = a.out / node / Path(*p.parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(member).read())
                records.append({'node': node, 'path': target.relative_to(a.out).as_posix()})
            inventory = json.load(tar.extractfile('metadata/inventory.json'))
        records.append({'node': node, 'archive_sha256': digest,
                        'captured_utc': inventory['timestamp_utc']})
    (a.out / 'PROCEDENCIA.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
    (a.out / 'LEER_ANTES_DE_PUBLICAR.md').write_text(
        '# Código recuperado del VNRT\n\n'
        'No es un instalador ni un respaldo completo. Revisar secretos incrustados antes de Git. '
        'Faltan intencionadamente config.json, SQL, claves, JAR, unidades y configuración de red. '
        'La restauración exacta usa los respaldos privados y la guía de recuperación. '
        'Los módulos duplicados en /opt se conservan por procedencia; no decidir cuál se ejecuta '
        'sin revisar ExecStart en el inventario privado.\n', encoding='utf-8')
    print('Código extraído para REVISIÓN. No se ejecutó Git ni se publicó nada.')


if __name__ == '__main__':
    main()
