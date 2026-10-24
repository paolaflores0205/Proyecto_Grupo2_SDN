"""Un ensayo de continuidad R1 en h1; no guarda credenciales ni cookies."""
import argparse
import datetime as dt
import getpass
import http.cookiejar
import json
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
    parser.add_argument('--hold-seconds', type=int, default=45)
    args = parser.parse_args()
    if not 35 <= args.hold_seconds <= 120:
        parser.error('La observacion debe durar entre 35 y 120 segundos')
    config = json.loads(Path(args.topology).read_text())
    controller_ip = config['nodes']['controller']['ip']
    portal = 'https://' + controller_ip
    lms = 'https://' + config['nodes']['h3']['ip'] + '/'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((controller_ip, 443))
        client_ip = route.getsockname()[0]
    if client_ip != config['nodes']['h1']['ip']:
        raise SystemExit('Ejecutar en h1 con la ruta de datos correcta.')
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
            return status == 200, 'HTTP_' + str(status)
        except urllib.error.HTTPError as error:
            return False, 'HTTP_' + str(error.code)
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise RuntimeError('Error TLS en LMS; revisar certificado') from None
            return False, 'sin_respuesta_' + type(error.reason).__name__
        except (TimeoutError, OSError) as error:
            return False, 'sin_respuesta_' + type(error).__name__

    record = {
        'trial_id': uuid.uuid4().hex[:12],
        'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'scenario': 'R1_continuidad_estudiante_h1',
        'hold_requested_s': args.hold_seconds,
        'continuity_poll_pause_s': 2,
        'continuity_samples': [],
        'client_ip': client_ip,
        'resource': lms,
        'clock': 'time.perf_counter_cliente',
        'post_login_poll_pause_s': 0.2,
        'probe_timeout_s': 1,
        'activation_limit_s': 20,
        'activation_ms': None,
        'login_and_panel_ms': None,
        'probe_count': 0,
        'outcome': 'no_ejecutado',
        'cleanup': 'no_login_enviado',
    }
    folder = Path.home() / 'evidencias-r1-continuidad'
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / ('continuidad-' + record['trial_id'] + '.json')
    started = False
    panel = ''
    failed = False
    try:
        _, html = fetch(portal + '/')
        accessible, observation = probe()
        record['baseline_observation'] = observation
        if '/logout' in html or accessible:
            record['outcome'] = 'baseline_no_limpia'
            raise RuntimeError('Hay sesion o acceso previo; revisar antes de medir')
        # Una respuesta HTTP previa no demuestra el descarte de red esperado.
        if observation.startswith('HTTP_'):
            record['outcome'] = 'baseline_no_concluyente'
            raise RuntimeError('LMS responde antes del login; revisar el estado inicial')
        token = csrf(html)
        print('Un ensayo con estudiante_demo: observara LMS durante', args.hold_seconds, 'segundos.')
        print('Introduce solo la contrasena. No cerrar la terminal durante la observacion.')
        username = 'estudiante_demo'
        password = getpass.getpass('Contrasena (no registrada): ')
        data = urllib.parse.urlencode({
            'username': username, 'password': password, 'csrf': token}).encode()
        password = ''
        started = True
        start = time.perf_counter()
        try:
            status, panel = fetch(portal + '/login', data)
        finally:
            data = b''
        record['login_and_panel_ms'] = round((time.perf_counter() - start) * 1000, 3)
        if status != 200 or '/logout' not in panel:
            record['outcome'] = 'panel_no_verificado'
            raise RuntimeError('El login no termino en un panel autenticado')
        while time.perf_counter() - start < record['activation_limit_s']:
            remaining = record['activation_limit_s'] - (time.perf_counter() - start)
            accessible, observation = probe(timeout=min(1, max(0.01, remaining)))
            elapsed = time.perf_counter() - start
            record['probe_count'] += 1
            record['last_observation'] = observation
            if accessible and elapsed <= record['activation_limit_s']:
                record['activation_ms'] = round(elapsed * 1000, 3)
                record['outcome'] = 'acceso_efectivo'
                break
            time.sleep(min(0.2, max(0, record['activation_limit_s'] - elapsed)))
        else:
            record['outcome'] = 'sin_acceso_dentro_del_limite'
        if record['outcome'] != 'acceso_efectivo':
            failed = True
        else:
            observation_start = time.perf_counter()
            print('Acceso conseguido; comienza la observacion de continuidad.')
            while True:
                accessible, observation = probe()
                elapsed = time.perf_counter() - observation_start
                sample = {'elapsed_s': round(elapsed, 3),
                          'accessible': accessible, 'observation': observation}
                record['continuity_samples'].append(sample)
                print('LMS', sample['elapsed_s'], 's:', observation, flush=True)
                if elapsed >= args.hold_seconds:
                    break
                time.sleep(min(2, args.hold_seconds - elapsed))
            samples = record['continuity_samples']
            record['continuity_observed_s'] = round(elapsed, 3)
            record['continuity_successes'] = sum(s['accessible'] for s in samples)
            record['continuity_failures'] = len(samples) - record['continuity_successes']
            record['outcome'] = ('continuidad_sin_fallos_detectados'
                                 if record['continuity_failures'] == 0
                                 else 'continuidad_con_fallos')
            failed = record['continuity_failures'] > 0
    except (Exception, KeyboardInterrupt) as error:
        failed = True
        if record['outcome'] == 'acceso_efectivo':
            record['outcome'] = 'error_durante_continuidad'
        if record['outcome'] == 'no_ejecutado':
            record['outcome'] = 'error_durante_login' if started else 'error_preparacion'
        record['error_type'] = type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            record['http_error'] = error.code
        # No guardar excepciones completas: podrian incluir datos de solicitudes.
        print('Ensayo detenido:', record['outcome'], record['error_type'])
    finally:
        if started:
            try:
                if '/logout' not in panel:
                    _, panel = fetch(portal + '/')
                if '/logout' in panel:
                    status, after = fetch(portal + '/logout', urllib.parse.urlencode({
                        'csrf': csrf(panel)}).encode())
                    if status == 200 and '/logout' not in after:
                        record['cleanup'] = 'logout_respondio_verificar_retiro'
                    else:
                        record['cleanup'] = 'logout_no_confirmado'
                        failed = True
                else:
                    record['cleanup'] = 'sin_panel_verificar_sesiones_en_controller'
                    failed = True
            except (Exception, KeyboardInterrupt) as error:
                record['cleanup'] = 'error_logout_' + type(error).__name__
                failed = True
        record['trial_duration_s'] = round(time.perf_counter() - start, 3) if started else None
        jar.clear()
        with path.open('x', encoding='utf-8') as output:
            json.dump(record, output, indent=2, ensure_ascii=False)
            output.write('\n')
        path.chmod(0o600)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        print('RESULTADO:', path)
        print('Sondeos discretos: pueden no detectar cortes entre consultas. Verificar retiro al terminar.')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
