"""Un ensayo de retiro por logout en h1; no mide la revocacion desde DTI."""
import argparse
import datetime as dt
import getpass
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--topology', default='/etc/sdn-g2/topology.json')
    parser.add_argument('--trust', default='/etc/sdn-g2/trust.pem')
    args = parser.parse_args()
    config = json.loads(Path(args.topology).read_text())
    portal_ip = config['nodes']['controller']['ip']
    portal = 'https://' + portal_ip
    lms = 'https://' + config['nodes']['h3']['ip'] + '/'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((portal_ip, 443))
        client_ip = route.getsockname()[0]
    if client_ip != config['nodes']['h1']['ip']:
        raise SystemExit('Ejecutar en h1 con ruta de datos correcta.')
    context = ssl.create_default_context(cafile=args.trust)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context))

    def fetch(url, data=None, timeout=8):
        with opener.open(url, data=data, timeout=timeout) as response:
            return response.status, response.read(1048576).decode('utf-8')

    def csrf(html):
        match = re.search(r'''name=["']csrf["'][^>]*value=["']([^"']+)''', html)
        if not match:
            raise RuntimeError('CSRF no encontrado')
        return match.group(1)

    def probe(timeout=1):
        try:
            status, _ = fetch(lms, timeout=timeout)
            return {'kind': 'http', 'accessible': status == 200,
                    'observation': 'HTTP_' + str(status)}
        except urllib.error.HTTPError as error:
            return {'kind': 'http', 'accessible': False,
                    'observation': 'HTTP_' + str(error.code)}
        except ssl.SSLError:
            raise RuntimeError('Error TLS en LMS') from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise RuntimeError('Error TLS en LMS') from None
            return {'kind': 'transport_error', 'accessible': False,
                    'observation': type(error.reason).__name__}
        except OSError as error:
            return {'kind': 'transport_error', 'accessible': False,
                    'observation': type(error).__name__}

    os.umask(0o077)
    folder = Path.home() / 'evidencias-r1-retiro-logout'
    folder.mkdir(mode=0o700, exist_ok=True)
    record = {
        'trial_id': uuid.uuid4().hex[:12],
        'scenario': 'R1_retiro_por_logout_estudiante_h1',
        'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'client_ip': client_ip, 'resource': lms,
        'clock': 'time.perf_counter_cliente',
        'probe_timeout_s': 1, 'poll_pause_s': 0.2,
        'observation_limit_s': 20,
        'logout_response_ms': None,
        'first_no_response_completed_ms': None,
        'first_no_response_probe_started_ms': None,
        'last_success_completed_ms_relative_logout': None,
        'confirmation_count': 0,
        'samples': [], 'outcome': 'no_ejecutado',
        'cleanup': 'no_login_enviado',
        'interpretation': 'Observacion cliente; confirmar SQL y OVS. No es latencia exacta de borrado ni medicion DTI.',
    }
    path = folder / ('retiro-' + record['trial_id'] + '.json')
    login_sent = False
    logout_verified = False
    panel = ''
    phase = 'preparacion'
    failed = True
    try:
        _, html = fetch(portal + '/')
        baseline = probe()
        record['baseline'] = baseline
        if '/logout' in html or baseline['kind'] != 'transport_error':
            raise RuntimeError('Estado inicial no limpio; revisar sesiones y acceso')
        print('Un ensayo en h1 con estudiante_demo. Sin sesion de navegador activa.')
        print('Mide logout hasta primer sondeo sin respuesta, con confirmaciones.')
        password = getpass.getpass('Contrasena (no registrada): ')
        data = urllib.parse.urlencode({
            'username': 'estudiante_demo', 'password': password,
            'csrf': csrf(html)}).encode()
        password = ''
        phase = 'login'
        login_sent = True
        try:
            status, panel = fetch(portal + '/login', data)
        finally:
            data = b''
        if status != 200 or '/logout' not in panel:
            raise RuntimeError('Panel autenticado no verificado')
        phase = 'verificar_acceso'
        deadline = time.perf_counter() + 20
        while time.perf_counter() < deadline:
            observation = probe()
            if observation['accessible']:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('LMS no accesible antes del logout')
        # Tres controles positivos antes de retirar la sesion.
        for _ in range(3):
            observation = probe()
            if not observation['accessible']:
                raise RuntimeError('Acceso inestable antes del logout')
            last_success = time.perf_counter()
            time.sleep(0.2)
        print('Acceso previo verificado: HTTP 200; se enviara logout.')
        data = urllib.parse.urlencode({'csrf': csrf(panel)}).encode()
        phase = 'logout'
        record['logout_requested_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        start = time.perf_counter()
        record['last_success_completed_ms_relative_logout'] = round(
            (last_success - start) * 1000, 3)
        try:
            status, after = fetch(portal + '/logout', data)
        finally:
            data = b''
        record['logout_response_ms'] = round((time.perf_counter() - start) * 1000, 3)
        if status != 200 or '/logout' in after:
            raise RuntimeError('Logout no confirmado por el portal')
        logout_verified = True
        record['cleanup'] = 'logout_respondio_verificar_sql_ovs'
        phase = 'observar_retiro'
        consecutive = 0
        first = None
        while time.perf_counter() - start < 20:
            begin = time.perf_counter() - start
            remaining = 20 - begin
            observation = probe(timeout=min(1, max(0.01, remaining)))
            end = time.perf_counter() - start
            sample = {'started_ms': round(begin * 1000, 3),
                      'completed_ms': round(end * 1000, 3), **observation}
            record['samples'].append(sample)
            print('Sondeo:', json.dumps(sample), flush=True)
            if end > 20:
                break
            if observation['kind'] == 'http' and not observation['accessible']:
                raise RuntimeError('LMS responde HTTP distinto de 200; no demuestra retiro de red')
            if observation['kind'] == 'transport_error':
                if first is None:
                    first = sample
                    record['first_no_response_completed_ms'] = sample['completed_ms']
                    record['first_no_response_probe_started_ms'] = sample['started_ms']
                consecutive += 1
            else:
                if first is not None:
                    raise RuntimeError('Acceso reaparecio tras el primer fallo; resultado inestable')
                record['last_success_completed_ms_relative_logout'] = sample['completed_ms']
                consecutive = 0
            record['confirmation_count'] = consecutive
            if consecutive >= 3:
                record['outcome'] = 'retiro_observado_pendiente_contraste_sql_ovs'
                failed = False
                break
            time.sleep(min(0.2, max(0, 20 - (time.perf_counter() - start))))
        if failed:
            record['outcome'] = 'sin_tres_confirmaciones_dentro_del_limite'
    except (Exception, KeyboardInterrupt) as error:
        record['outcome'] = 'error_' + phase
        record['error_type'] = type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            record['http_error'] = error.code
        print('Ensayo detenido en:', phase, type(error).__name__)
    finally:
        if login_sent and not logout_verified:
            try:
                _, fresh = fetch(portal + '/')
                if '/logout' in fresh:
                    status, after = fetch(portal + '/logout', urllib.parse.urlencode(
                        {'csrf': csrf(fresh)}).encode())
                    if status == 200 and '/logout' not in after:
                        record['cleanup'] = 'logout_recuperacion_verificar_sql_ovs'
                    else:
                        record['cleanup'] = 'logout_recuperacion_no_confirmado'
                else:
                    record['cleanup'] = 'sin_panel_verificar_sesiones_controller'
            except (Exception, KeyboardInterrupt) as error:
                record['cleanup'] = 'error_limpieza_' + type(error).__name__
        jar.clear()
        with path.open('x', encoding='utf-8') as output:
            json.dump(record, output, indent=2, ensure_ascii=False)
            output.write('\n')
        path.chmod(0o600)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        print('RESULTADO:', path)
        print('El tiempo incluye respuesta del portal y timeout del sondeo.')
        print('No prueba por si solo el descarte. Verificar SQL y OVS antes de repetir.')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
