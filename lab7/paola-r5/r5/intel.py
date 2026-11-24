"""R5-03, R5-04 y R5-06: listas negra/blanca de IPs y dominios."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, List, Optional, Tuple, Union

from .alerts import normalize_domain

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class FeedRejected(ValueError):
    """El feed no trae ninguna entrada valida: se conserva la lista anterior."""


@dataclass
class FeedReport:
    added_networks: List[str] = field(default_factory=list)
    removed_networks: List[str] = field(default_factory=list)
    added_domains: List[str] = field(default_factory=list)
    removed_domains: List[str] = field(default_factory=list)
    ignored: List[Tuple[int, str, str]] = field(default_factory=list)  # (linea, texto, motivo)


def _net(text: str) -> Optional[Network]:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


class ThreatIntel:
    """Inteligencia de amenazas local. La lista blanca siempre gana."""

    def __init__(self, whitelist: Iterable[Network] = (), blacklist: Iterable[str] = (),
                 min_prefix_v4: int = 16, min_prefix_v6: int = 32):
        self.whitelist: Tuple[Network, ...] = tuple(whitelist)
        # Un feed envenenado con 0.0.0.0/0 bloquearia todo Internet: se rechazan redes amplias.
        self.min_prefix = {4: min_prefix_v4, 6: min_prefix_v6}
        self.black_networks: FrozenSet[Network] = frozenset()
        self.black_domains: FrozenSet[str] = frozenset()
        if blacklist:
            self.update_blacklist(blacklist)

    def is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return any(addr in net for net in self.whitelist)

    def is_malicious_ip(self, ip: str) -> bool:
        """True solo si la IP esta en la lista negra y no en la blanca."""
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        if self.is_whitelisted(ip):
            return False
        return any(addr in net for net in self.black_networks)

    def is_malicious_domain(self, domain: str) -> bool:
        """True si el dominio o alguno de sus dominios padre esta en la lista negra.

        Compara por etiquetas completas: 'x.malware.example' coincide con
        'malware.example', pero 'notmalware.example' no.
        """
        name = normalize_domain(domain)
        if name is None:
            return False
        labels = name.split(".")
        return any(".".join(labels[i:]) in self.black_domains for i in range(len(labels)))

    def update_blacklist(self, feed: Union[str, Iterable[str]]) -> FeedReport:
        """Reemplaza la lista negra con el feed validado y devuelve el reporte de cambios.

        - Lineas vacias y comentarios ('#') se saltan.
        - Entradas invalidas, que caen en la lista blanca o mas amplias que el minimo
          permitido (por defecto /16 en IPv4) se ignoran y se reportan.
        - Si no queda ninguna entrada valida se lanza FeedRejected y no cambia nada.
        """
        lines = feed.splitlines() if isinstance(feed, str) else list(feed)
        networks, domains = set(), set()
        report = FeedReport()
        for number, original in enumerate(lines, start=1):
            text = str(original).split("#", 1)[0].strip()
            if not text:
                continue
            net = _net(text)
            if net is not None:
                if net.prefixlen < self.min_prefix[net.version]:
                    report.ignored.append((number, text, f"red demasiado amplia (/{net.prefixlen}); "
                                                         f"el minimo es /{self.min_prefix[net.version]}"))
                    continue
                if any(net.subnet_of(w) for w in self.whitelist if w.version == net.version):
                    report.ignored.append((number, text, "esta en la lista blanca"))
                    continue
                networks.add(net)
                continue
            domain = normalize_domain(text)
            if domain is not None and "." in domain:
                domains.add(domain)
                continue
            report.ignored.append((number, text, "no es IP, red ni dominio valido"))
        if not networks and not domains:
            raise FeedRejected("El feed no tiene entradas validas; se conserva la lista anterior")
        report.added_networks = sorted(str(n) for n in networks - self.black_networks)
        report.removed_networks = sorted(str(n) for n in self.black_networks - networks)
        report.added_domains = sorted(domains - self.black_domains)
        report.removed_domains = sorted(self.black_domains - domains)
        self.black_networks, self.black_domains = frozenset(networks), frozenset(domains)
        return report
