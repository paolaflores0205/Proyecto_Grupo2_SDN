#!/usr/bin/env python3
"""Reuse the unchanged LMS demo; replace only its obsolete fixed-permission notice."""
import ssl
import vnrt_lms_https_paso3 as lms
old='El permiso actual es fijo y de prueba: h1 permitido; h2 bloqueado.'.encode('utf-8')
new='El acceso HTTPS depende de la sesión y del rol del portal (R1). Estudiante, docente y administrativo pueden acceder desde su terminal autenticado; visitante y terminal sin sesión no tienen permiso.'.encode('utf-8')
if old not in lms.PAGE: raise RuntimeError('Expected historical notice not found; review content')
lms.PAGE=lms.PAGE.replace(old,new)
if __name__=='__main__':
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(lms.ROOT/'server.crt',lms.ROOT/'server.key')
    server=lms.ThreadingHTTPServer(('192.0.2.101',443),lms.Handler)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    print('LMS HTTPS listening; notice aligned with session-based R1',flush=True)
    server.serve_forever()
