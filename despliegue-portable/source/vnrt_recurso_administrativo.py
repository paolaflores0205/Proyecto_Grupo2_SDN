"""Fictional read-only resource on h4:8443; NOT the controller's DTI console."""
import json,ssl
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
PAGE='''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sistema administrativo · SDN G2</title><style>body{font:18px system-ui;background:#f4f6f8;color:#243447}main{max-width:850px;margin:40px auto;background:white;padding:32px;border-top:6px solid #254d76}td,th{padding:14px;border:1px solid #aaa}table{border-collapse:collapse;width:100%}</style><main><p>TEL354 · Grupo 2 · Recurso protegido R2</p><h1>Sistema administrativo de prueba</h1><p>Acceso de red reservado al rol Administrativo.</p><table><tr><th>Trámite ficticio</th><th>Estado de ejemplo</th></tr><tr><td>DEMO-ADM-001</td><td>Registrado</td></tr><tr><td>DEMO-ADM-002</td><td>Pendiente</td></tr></table><p>AVZ7_ADMINISTRACION_OK. Datos ficticios de lectura. No es una plataforma institucional ni la consola DTI. No permite modificar expedientes.</p><p>h4 · 192.0.2.102 · HTTPS TCP 8443</p></main></html>'''.encode()
class Handler(BaseHTTPRequestHandler):
    server_version='SDN-Recurso-Administrativo/1.0';sys_version=''
    def do_GET(self):
        if self.path=='/health':body=json.dumps({'status':'ok','resource':'administracion','data':'fictional-read-only','port':8443}).encode();typ='application/json';code=200
        elif self.path=='/':body=PAGE;typ='text/html; charset=utf-8';code=200
        else:body=b'Not found';typ='text/plain';code=404
        self.send_response(code);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers();self.wfile.write(body)
    def setup(self):self.request.settimeout(10);super().setup()
if __name__=='__main__':
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain('/opt/sdn-notas-paso6/server.crt','/opt/sdn-notas-paso6/server.key')
    server=ThreadingHTTPServer(('192.0.2.102',8443),Handler);server.socket=ctx.wrap_socket(server.socket,server_side=True)
    server.serve_forever()
