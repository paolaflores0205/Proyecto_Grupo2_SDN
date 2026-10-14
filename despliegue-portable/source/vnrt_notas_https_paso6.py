#!/usr/bin/env python3
"""Read-only fictional privileged resource. SDN enforces network admission, not course-specific edits."""
import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import ssl
ROOT=Path('/opt/sdn-notas-paso6')
PAGE='''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Notas de prueba · SDN G2</title><style>body{font:17px system-ui;background:#f4f6f8;color:#203246;margin:0}main{max-width:850px;margin:48px auto;padding:32px;background:white;border-top:7px solid #254d76;border-radius:8px}small{color:#526475}h1{font-size:32px}table{width:100%;border-collapse:collapse;margin:24px 0}th,td{padding:14px;border-bottom:1px solid #c9d3df;text-align:left}.notice{background:#fff5d8;padding:18px;border-left:4px solid #ba922a}.scroll{overflow-x:auto}a{color:#254d76}@media(max-width:600px){main{margin:20px 12px;padding:22px}h1{font-size:27px}}</style></head><body><main><small>TEL354 · Grupo 2 · Recurso privilegiado R2</small><h1>Sistema de notas de prueba</h1><p>La conexión HTTPS al recurso protegido funciona. El rol docente tiene permiso de red a este servicio según la política de MySQL.</p><div class="scroll"><table><thead><tr><th>Curso ficticio</th><th>Registro ficticio</th><th>Nota de ejemplo</th></tr></thead><tbody><tr><td>Redes de demostración</td><td>DEMO-001</td><td>16</td></tr><tr><td>Redes de demostración</td><td>DEMO-002</td><td>18</td></tr></tbody></table></div><p class="notice">PASO6_NOTAS_OK. Todos los datos son ficticios y de lectura. No es el sistema de notas de la PUCP, no contiene expedientes reales y no permite cambiar calificaciones. R2 aquí restringe la conexión al servicio; los permisos por curso o edición requerirían autorización adicional en la aplicación.</p><p>Servidor h4 · 192.0.2.102 · HTTPS TCP 443.</p><p><a href="/health">Consultar estado</a></p></main></body></html>'''.encode('utf-8')

class Handler(BaseHTTPRequestHandler):
    server_version='SDN-Notas-Lab/1.0'; sys_version=''
    def response(self,head=False):
        if self.path in ('/','/index.html'): body=PAGE; code=200; content='text/html; charset=utf-8'
        elif self.path=='/health':
            body=json.dumps({'status':'ok','resource':'notas-demo','host':'h4','step':6,'data':'fictional-read-only'}).encode(); code=200; content='application/json'
        else: body=b'Not found'; code=404; content='text/plain'
        self.send_response(code); self.send_header('Content-Type',content); self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if not head: self.wfile.write(body)
    def do_GET(self): self.response()
    def do_HEAD(self): self.response(True)
    def setup(self): self.request.settimeout(10); super().setup()

if __name__=='__main__':
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT/'server.crt',ROOT/'server.key')
    server=ThreadingHTTPServer(('192.0.2.102',443),Handler)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    print('Notas HTTPS listening on 192.0.2.102:443; fictional read-only data',flush=True)
    server.serve_forever()
