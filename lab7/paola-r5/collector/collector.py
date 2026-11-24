"""Colector sdn-r5 (VM suricata): lee eve.json del Suricata principal y envia los eventos
utiles al servicio sdn-r5 de la VM app por mTLS.

- Solo envia alert, dns, tls y http, y solo si al menos un extremo es externo.
- Empieza al final del archivo (no reenvia historia) y guarda un cursor (inodo, posicion).
- Si el archivo rota o se trunca (logrotate con copytruncate), vuelve al inicio.
- Si el envio falla, no avanza el cursor: reintenta (entrega al menos una vez; el
  servicio descarta duplicados).

Uso: python3 collector.py --config /etc/sdn-r5/collector.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

WANTED = {"alert", "dns", "tls", "http"}


def is_relevant(line: str, internal: Iterable) -> bool:
    """Filtro barato antes de enviar: tipo util y al menos un extremo fuera de las redes internas."""
    try:
        ev = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(ev, dict) or ev.get("event_type") not in WANTED:
        return False
    for key in ("src_ip", "dest_ip"):
        try:
            addr = ipaddress.ip_address(ev.get(key))
        except (TypeError, ValueError):
            return False
        if not any(addr in net for net in internal):
            return True
    return False


class Cursor:
    """Posicion de lectura persistente: (inodo, offset)."""

    def __init__(self, path: Path):
        self.path = path
        self.inode: Optional[int] = None
        self.offset = 0
        if path.exists():
            try:
                raw = json.loads(path.read_text())
                self.inode, self.offset = raw["inode"], int(raw["offset"])
            except (ValueError, KeyError, TypeError):
                pass

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": self.inode, "offset": self.offset}))
        os.replace(tmp, self.path)


def read_batch(eve: Path, cursor: Cursor, max_lines: int, start_at_end: bool) -> Tuple[List[str], int]:
    """Lee lineas completas desde el cursor. Devuelve (lineas, offset nuevo); no guarda."""
    try:
        st = eve.stat()
    except FileNotFoundError:
        return [], cursor.offset
    if cursor.inode is None:  # primera ejecucion
        cursor.inode, cursor.offset = st.st_ino, (st.st_size if start_at_end else 0)
    elif cursor.inode != st.st_ino or cursor.offset > st.st_size:
        cursor.inode, cursor.offset = st.st_ino, 0  # rotado o truncado
    lines: List[str] = []
    with eve.open("rb") as fh:
        fh.seek(cursor.offset)
        offset = cursor.offset
        while len(lines) < max_lines:
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                break  # nada mas o linea a medio escribir
            offset += len(raw)
            lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))
    return lines, offset


def client_tls_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    return ctx


def make_sender(url: str, ctx: Optional[ssl.SSLContext], timeout: float = 10.0) -> Callable[[List[str]], dict]:
    def send(lines: List[str]) -> dict:
        data = json.dumps({"lines": lines}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read() or b"{}")
    return send


def run_once(eve: Path, cursor: Cursor, internal, send, max_lines: int = 500,
             start_at_end: bool = True) -> dict:
    lines, new_offset = read_batch(eve, cursor, max_lines, start_at_end)
    useful = [l for l in lines if is_relevant(l, internal)]
    result = {"read": len(lines), "sent": 0}
    if useful:
        reply = send(useful)  # si falla lanza excepcion y el cursor no avanza
        result.update(sent=len(useful), reply=reply)
    cursor.offset = new_offset
    cursor.save()
    return result


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Colector de eve.json para sdn-r5")
    p.add_argument("--config", default="/etc/sdn-r5/collector.json")
    args = p.parse_args(argv)
    cfg = json.loads(Path(args.config).read_text())
    internal = [ipaddress.ip_network(n) for n in cfg["internal_networks"]]
    tls = cfg["tls"]
    send = make_sender(cfg["receiver_url"], client_tls_context(tls["cert"], tls["key"], tls["ca"]))
    eve, cursor = Path(cfg["eve"]), Cursor(Path(cfg["state"]))
    poll, backoff = float(cfg.get("poll_seconds", 0.5)), 1.0
    print(json.dumps({"status": "collecting", "eve": str(eve), "receiver": cfg["receiver_url"]}), flush=True)
    while True:
        try:
            r = run_once(eve, cursor, internal, send, int(cfg.get("batch_lines", 500)))
            if r["sent"]:
                print(json.dumps(r, ensure_ascii=False), flush=True)
            backoff = 1.0
            if r["read"] == 0:
                time.sleep(poll)
        except Exception as exc:  # receptor caido: reintentar sin perder eventos
            print(json.dumps({"error": str(exc), "retry_in_s": backoff}), file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)


if __name__ == "__main__":
    main()
