"""Registro atomico de plazos originales. No reinstala reglas de Floodlight."""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from .rules import build_perimeter_rule, rule_names


class RecoveryError(RuntimeError):
    """No hay informacion suficiente para reconciliar sin inventar un plazo."""


class BlockState:
    def __init__(self, path, policy):
        self.path = Path(path) if path is not None else None
        self.policy = policy

    def _validate(self, raw):
        if (not isinstance(raw, dict) or raw.get('schema_version') != 1
                or raw.get('edge_dpid') != self.policy.edge_dpid
                or raw.get('edge_port') != self.policy.edge_port
                or raw.get('rule_prefix') != self.policy.rule_prefix
                or not isinstance(raw.get('blocks'), dict)):
            raise RecoveryError('Registro de bloqueos incompatible con la politica')
        for ip, block in raw['blocks'].items():
            try:
                if str(ipaddress.IPv4Address(ip)) != ip or not isinstance(block, dict):
                    raise ValueError('IP o bloque invalido')
                # El diario nunca autoriza borrar nombres ajenos ni bloquear una IP protegida.
                build_perimeter_rule(ip, self.policy, 1)
                if block['ip'] != ip or set(block['rules']) != set(rule_names(ip, self.policy).values()):
                    raise ValueError('Nombres de reglas inconsistentes')
                start = datetime.fromisoformat(block['installed_at'])
                end = datetime.fromisoformat(block['expires_at'])
                if start.tzinfo is None or end.tzinfo is None or end <= start:
                    raise ValueError('Plazo de bloqueo invalido')
                if not 0 < (end - start).total_seconds() <= 65535:
                    raise ValueError('Duracion fuera del limite OpenFlow')
                if block.get('status') not in {'pending', 'submitted', 'partial', 'cleanup_pending'}:
                    raise ValueError('Estado invalido')
                if type(block.get('policy_rule')) is not int or not 0 <= block['policy_rule'] <= 6:
                    raise ValueError('Regla de politica invalida')
            except (KeyError, TypeError, ValueError) as exc:
                raise RecoveryError(f'Registro de bloqueo invalido para {ip}: {exc}') from exc
        return raw['blocks']

    def load(self):
        if self.path is None or not self.path.exists():
            return {}
        try:
            return self._validate(json.loads(self.path.read_text(encoding='utf-8')))
        except (OSError, ValueError, TypeError) as exc:
            raise RecoveryError(f'No se pudo leer el registro de bloqueos: {exc}') from exc

    def save(self, blocks):
        if self.path is None:
            return
        raw = {'schema_version': 1, 'edge_dpid': self.policy.edge_dpid,
               'edge_port': self.policy.edge_port, 'rule_prefix': self.policy.rule_prefix,
               'blocks': blocks}
        self._validate(raw)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.' + self.path.name + '-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file:
                json.dump(raw, file, ensure_ascii=False, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
