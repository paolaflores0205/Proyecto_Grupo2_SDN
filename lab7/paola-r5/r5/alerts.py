"""R5-01: lectura robusta de eventos de Suricata (eve.json)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional, Union

from .model import Alert

SUPPORTED_EVENTS = {"alert", "dns", "tls", "http"}
_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")
_HOSTNAME = re.compile(r"(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*")


def normalize_domain(value: Any) -> Optional[str]:
    """Minusculas, sin espacios ni punto final. Devuelve None si no es un nombre de host."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    if not name or not _HOSTNAME.fullmatch(name):
        return None
    if name.rsplit(".", 1)[-1].isdigit():  # IP literal (valida o no): un TLD nunca es numerico
        return None
    return name


def _timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    text = _TZ_NO_COLON.sub(r"\1:\2", value.strip())  # Suricata escribe +0000
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _ip(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def _port(value: Any) -> Optional[int]:
    if type(value) is int and 0 <= value <= 65535:
        return value
    return None


def _dns_fields(dns: dict) -> tuple:
    rrname = dns.get("rrname")
    if rrname is None and isinstance(dns.get("queries"), list) and dns["queries"]:
        rrname = dns["queries"][0].get("rrname")  # formato v3
    ips = []
    for answer in dns.get("answers") or []:
        if isinstance(answer, dict) and answer.get("rrtype") in ("A", "AAAA"):
            ips.append(answer.get("rdata"))
    grouped = dns.get("grouped") or {}
    if isinstance(grouped, dict):
        for kind in ("A", "AAAA"):
            ips.extend(grouped.get(kind) or [])
    valid = []
    for item in ips:
        ip = _ip(item)
        if ip and ip not in valid:
            valid.append(ip)
    return normalize_domain(rrname), tuple(valid)


def parse_ids_alert(line: Union[str, bytes, None]) -> Optional[Alert]:
    """Convierte una linea de eve.json en un Alert, o devuelve None si no sirve.

    Nunca lanza excepciones: una linea rota, vacia o de un tipo no soportado
    se descarta para que el colector siga leyendo.
    """
    if line is None:
        return None
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    text = line.strip()
    if not text:
        return None
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    event_type = raw.get("event_type")
    if event_type not in SUPPORTED_EVENTS:
        return None
    ts = _timestamp(raw.get("timestamp"))
    src, dst = _ip(raw.get("src_ip")), _ip(raw.get("dest_ip"))
    proto = raw.get("proto")
    if ts is None or src is None or dst is None or not isinstance(proto, str):
        return None

    fields = dict(
        event_type=event_type, timestamp=ts, src_ip=src, dest_ip=dst,
        proto=proto.upper(), src_port=_port(raw.get("src_port")),
        dest_port=_port(raw.get("dest_port")),
        flow_id=raw.get("flow_id") if type(raw.get("flow_id")) is int else None,
        in_iface=raw.get("in_iface") if isinstance(raw.get("in_iface"), str) else None,
    )
    if event_type == "alert":
        alert = raw.get("alert")
        if not isinstance(alert, dict) or type(alert.get("signature_id")) is not int:
            return None
        severity = alert.get("severity")
        fields.update(
            signature_id=alert["signature_id"],
            signature=alert.get("signature") if isinstance(alert.get("signature"), str) else None,
            category=alert.get("category") if isinstance(alert.get("category"), str) else None,
            severity=severity if type(severity) is int and 1 <= severity <= 4 else None,
        )
        # Una alerta puede traer metadatos de la capa de aplicacion
        for key, attr in (("tls", "sni"), ("http", "hostname")):
            sub = raw.get(key)
            if isinstance(sub, dict) and normalize_domain(sub.get(attr)):
                fields["domain"] = normalize_domain(sub.get(attr))
    elif event_type == "dns":
        dns = raw.get("dns")
        if not isinstance(dns, dict):
            return None
        domain, ips = _dns_fields(dns)
        if domain is None:
            return None
        fields.update(domain=domain, resolved_ips=ips)
    elif event_type == "tls":
        tls = raw.get("tls")
        fields["domain"] = normalize_domain(tls.get("sni")) if isinstance(tls, dict) else None
    else:  # http
        http = raw.get("http")
        fields["domain"] = normalize_domain(http.get("hostname")) if isinstance(http, dict) else None
    # Solo se fusionan registros iguales. El flujo, la transaccion, la URL y la
    # hora exacta se conservan: compartir conexion o firma no prueba duplicidad.
    canonical = {k: v for k, v in raw.items()
                 if k not in {"in_iface", "pcap_cnt", "pkt_src"}}
    canonical["timestamp"] = ts.isoformat()
    fields["event_id"] = hashlib.sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()
    return Alert(**fields)
