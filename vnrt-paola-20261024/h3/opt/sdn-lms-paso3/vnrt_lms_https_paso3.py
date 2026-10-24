#!/usr/bin/env python3
"""Fixed educational HTTPS resource. Not production LMS or login portal."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl

ROOT=Path('/opt/sdn-lms-paso3')
PAGE='''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LMS de prueba · SDN G2</title><style>body{font:18px system-ui;background:#f4f6f8;color:#203246;margin:0}main{max-width:850px;margin:60px auto;padding:35px;background:white;border-top:7px solid #254d76;border-radius:8px}small{color:#526475}h1{font-size:32px}li{margin:12px 0}.notice{background:#fff5d8;padding:18px;border-left:4px solid #ba922a}a{color:#254d76}</style>
<main><small>TEL354 · Grupo 2 · Recurso del VNRT</small><h1>LMS / Paideia de prueba</h1>
<p>La conexión HTTPS al recurso académico funciona.</p><ul><li>Curso de demostración: Redes definidas por software.</li><li>Material: contenido ficticio, sin datos personales.</li><li>Servidor: h3 · 192.0.2.3 · TCP 443.</li></ul>
<p class="notice">PASO3_LMS_OK. Este recurso representa un servicio del campus; no es Paideia real ni el portal de autenticación. El acceso depende de una sesión vigente y del rol. Estudiante y docente tienen permiso; administrativo y visitante no tienen permiso a LMS.</p>
<p><a href="/health">Consultar estado del recurso</a></p></main></html>'''.encode('utf-8')

class Handler(BaseHTTPRequestHandler):
    server_version='SDN-LMS-Lab/1.0'
    sys_version=''
    def response(self, head=False):
        if self.path in ('/','/index.html'):
            body=PAGE; code=200; content='text/html; charset=utf-8'
        elif self.path=='/health':
            body=json.dumps({'status':'ok','resource':'LMS-demo','host':'h3','step':3}).encode(); code=200; content='application/json'
        else:
            body=b'Not found'; code=404; content='text/plain'
        self.send_response(code)
        self.send_header('Content-Type',content)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if not head: self.wfile.write(body)
    def do_GET(self): self.response()
    def do_HEAD(self): self.response(True)
    def setup(self):
        self.request.settimeout(10)
        super().setup()

if __name__=='__main__':
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT/'server.crt',ROOT/'server.key')
    server=ThreadingHTTPServer(('192.0.2.3',443),Handler)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    print('LMS HTTPS listening on 192.0.2.3:443',flush=True)
    server.serve_forever()
