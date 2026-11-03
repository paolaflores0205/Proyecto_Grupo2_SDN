"""Ensayo exploratorio R1 en h1/h2: inicio programado y sesion mantenida."""
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


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', choices=['h1', 'h2'], required=True)
    parser.add_argument('--batch', required=True, help='Etiqueta comun de la pareja o del control individual')
    parser.add_argument('--start-at', help='Hora comun ISO con zona UTC; omitir para control individual inmediato')
    parser.add_argument('--hold-seconds', type=int, default=60)
    parser.add_argument('--topology', default='/etc/sdn-g2/topology.json')
    parser.add_argument('--trust', default='/etc/sdn-g2/trust.pem')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', args.batch):
        parser.error('--batch: usar de 1 a 48 letras, numeros, guiones o guiones bajos')
    if not 10 <= args.hold_seconds <= 180:
        parser.error('--hold-seconds debe estar entre 10 y 180')
    target = None
    if args.start_at:
        try:
            planned = dt.datetime.fromisoformat(args.start_at.replace('Z', '+00:00'))
            if planned.tzinfo is None or planned.utcoffset() != dt.timedelta(0):
                raise ValueError()
            target = planned.timestamp()
        except ValueError:
            parser.error('--start-at debe ser ISO con zona UTC, por ejemplo 2026-10-22T04:00:00Z')
        if not 0 < target - time.time() <= 900:
            parser.error('La hora de inicio debe estar en el futuro, a no mas de 15 minutos')
    config = json.loads(Path(args.topology).read_text())
    ip = config['nodes']['controller']['ip']
    portal = 'https://' + ip
    lms = 'https://' + config['nodes']['h3']['ip'] + '/'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((ip, 443))
        client_ip = route.getsockname()[0]
    if client_ip != config['nodes'][args.client]['ip']:
        raise SystemExit('Cliente/ruta incorrectos: revisar --client y la interfaz de datos.')
    context = ssl.create_default_context(cafile=args.trust)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar),
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
            return {'kind': 'http', 'accessible': status == 200, 'observation': 'HTTP_' + str(status)}
        except urllib.error.HTTPError as error:
            return {'kind': 'http', 'accessible': False, 'observation': 'HTTP_' + str(error.code)}
        except ssl.SSLError:
            raise RuntimeError('Error TLS en LMS') from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise RuntimeError('Error TLS en LMS') from None
            return {'kind': 'transport_error', 'accessible': False,
                    'observation': type(error.reason).__name__}
        except OSError as error:
            return {'kind': 'transport_error', 'accessible': False, 'observation': type(error).__name__}

    os.umask(0o077)
    folder = Path.home() / 'evidencias-r1-concurrencia'
    folder.mkdir(mode=0o700, exist_ok=True)
    record = {
        'trial_id': uuid.uuid4().hex[:12], 'batch': args.batch,
        'client': args.client, 'client_ip': client_ip,
        'scenario': 'R1_activacion_y_sesion_mantenida',
        'mode': 'inicio_programado' if target is not None else 'control_individual',
        'planned_start_utc': args.start_at,
        'clock_durations': 'time.perf_counter_cliente',
        'clock_utc': 'reloj_SO_NTP_sin_cota_de_error_medida',
        'probe_timeout_s': 1, 'activation_poll_pause_s': 0.2,
        'activation_limit_s': 20, 'hold_requested_s': args.hold_seconds,
        'hold_poll_pause_s': 2,
        'login_requested_utc': None, 'activation_observed_utc': None,
        'login_and_panel_ms': None, 'activation_ms': None,
        'hold_samples': [], 'outcome': 'no_ejecutado',
        'cleanup': 'no_login_enviado',
        'limits': 'Solo h1/h2; contrastar solapamiento, SQL y OVS. No capacidad maxima ni tiempo aislado de instalacion de reglas.',
    }
    path = folder / (args.batch + '-' + args.client + '-' + record['trial_id'] + '.json')
    login_sent = False
    panel = ''
    phase = 'preparacion'
    failed = True
    data = b''
    try:
        baseline = probe()
        record['baseline'] = baseline
        if baseline['kind'] != 'transport_error':
            raise RuntimeError('Acceso o respuesta HTTP previa; revisar estado inicial')
        print('Cliente:', args.client, client_ip, '| lote:', args.batch, flush=True)
        print('Usar estudiante_demo. No abrir otra sesion en este terminal.', flush=True)
        password = getpass.getpass('Contrasena (no registrada): ')
        # Obtener formulario fresco tras introducir la clave, antes de esperar la hora comun.
        _, html = fetch(portal + '/')
        if '/logout' in html:
            password = ''
            raise RuntimeError('Sesion previa detectada por el portal')
        data = urllib.parse.urlencode({'username': 'estudiante_demo',
                                      'password': password, 'csrf': csrf(html)}).encode()
        password = ''
        if target is not None:
            if time.time() >= target:
                raise RuntimeError('Hora programada alcanzada antes de estar listo; repetir pareja')
            print('LISTO. Esperando inicio UTC:', args.start_at, flush=True)
            while time.time() < target:
                time.sleep(min(0.1, max(0, target - time.time())))
            lateness = time.time() - target
            record['scheduled_start_lateness_ms'] = round(lateness * 1000, 3)
            if lateness > 0.5:
                raise RuntimeError('Inicio mas de 500 ms tarde; repetir pareja')
        phase = 'login'
        record['login_requested_utc'] = utcnow()
        start = time.perf_counter()
        login_sent = True
        print('Enviando login:', record['login_requested_utc'], flush=True)
        try:
            status, panel = fetch(portal + '/login', data)
        finally:
            data = b''
        record['login_and_panel_ms'] = round((time.perf_counter() - start) * 1000, 3)
        if status != 200 or '/logout' not in panel:
            raise RuntimeError('Panel autenticado no verificado')
        phase = 'activacion'
        while time.perf_counter() - start < 20:
            remaining = 20 - (time.perf_counter() - start)
            observation = probe(timeout=min(1, max(0.01, remaining)))
            elapsed = time.perf_counter() - start
            if observation['accessible'] and elapsed <= 20:
                record['activation_ms'] = round(elapsed * 1000, 3)
                record['activation_observed_utc'] = utcnow()
                break
            time.sleep(min(0.2, max(0, 20 - (time.perf_counter() - start))))
        else:
            raise RuntimeError('Sin acceso dentro del limite de activacion')
        phase = 'sesion_mantenida'
        print('LMS activo; activacion_ms =', record['activation_ms'], flush=True)
        print('Manteniendo sesion durante', args.hold_seconds, 'segundos.', flush=True)
        hold_start = time.perf_counter()
        record['hold_started_utc'] = utcnow()
        while time.perf_counter() - hold_start < args.hold_seconds:
            observation = probe()
            sample = {'elapsed_s': round(time.perf_counter() - hold_start, 3),
                      'timestamp_utc': utcnow(), **observation}
            record['hold_samples'].append(sample)
            print('LMS:', json.dumps(sample), flush=True)
            time.sleep(min(2, max(0, args.hold_seconds - (time.perf_counter() - hold_start))))
        record['hold_completed_utc'] = utcnow()
        record['hold_successes'] = sum(s['accessible'] for s in record['hold_samples'])
        record['hold_failures'] = len(record['hold_samples']) - record['hold_successes']
        failed = record['hold_failures'] > 0
        record['outcome'] = 'sesion_con_fallos' if failed else 'acceso_y_sesion_sin_fallos_detectados'
    except (Exception, KeyboardInterrupt) as error:
        failed = True
        record['outcome'] = 'error_' + phase
        record['error_type'] = type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            record['http_error'] = error.code
        print('Ensayo detenido en:', phase, type(error).__name__, flush=True)
    finally:
        data = b''
        if login_sent:
            try:
                if '/logout' not in panel:
                    _, panel = fetch(portal + '/')
                if '/logout' in panel:
                    record['logout_requested_utc'] = utcnow()
                    status, after = fetch(portal + '/logout', urllib.parse.urlencode(
                        {'csrf': csrf(panel)}).encode())
                    if status == 200 and '/logout' not in after:
                        record['cleanup'] = 'logout_respondio_verificar_sql_ovs'
                    else:
                        record['cleanup'] = 'logout_no_confirmado'
                        failed = True
                else:
                    record['cleanup'] = 'sin_panel_verificar_sesiones_controller'
                    failed = True
            except (Exception, KeyboardInterrupt) as error:
                record['cleanup'] = 'error_logout_' + type(error).__name__
                failed = True
        jar.clear()
        with path.open('x', encoding='utf-8') as output:
            json.dump(record, output, indent=2, ensure_ascii=False)
            output.write('\n')
        path.chmod(0o600)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        print('RESULTADO:', path)
        print('Verificar SQL/OVS y la pareja antes de repetir. Sondeos discretos.')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
