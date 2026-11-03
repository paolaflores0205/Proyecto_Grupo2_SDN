import json,os,select,socket,time
from pathlib import Path
import pymysql
from vnrt_flujos_https_paso3 import HOSTS,DPID
CLIENTS={HOSTS[n][3]:n for n in ("h1","h2")}
SOCKET="/run/sdn-r1/policy.sock"
def db():
    CONFIG = json.loads(Path('/etc/sdn-portal-paso4/config.json').read_text())
    return pymysql.connect(host='127.0.0.1', user=CONFIG['db_user'], password=CONFIG['db_password'], database='sdn_g2', charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor, autocommit=True, connect_timeout=3, read_timeout=3, write_timeout=3)

def sync_request():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(15)
        conn.connect(SOCKET)
        conn.sendall(b'{"action":"sync"}\n')
        data = b''
        while b'\n' not in data:
            part = conn.recv(4096)
            if not part or len(data) > 16384:
                raise RuntimeError('Invalid policy response')
            data += part
    result = json.loads(data)
    if not result.get('ok'):
        raise RuntimeError('Policy adapter unavailable')
    return result

def daemon():
    reconciler = Reconciler()
    if os.path.exists(SOCKET):
        import stat
        if not stat.S_ISSOCK(os.stat(SOCKET).st_mode):
            raise RuntimeError('Unexpected runtime file')
        os.unlink(SOCKET)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCKET)
        os.chmod(SOCKET, 384)
        server.listen(8)
        while True:
            ready, _, _ = select.select([server], [], [], 2)
            conn = None
            try:
                if ready:
                    conn, _ = server.accept()
                    conn.settimeout(2)
                    raw = conn.recv(4096)
                    if raw != b'{"action":"sync"}\n':
                        raise RuntimeError('Invalid local request')
                result = reconciler.sync()
            except Exception as error:
                reconciler.fail_closed()
                result = {'ok': False}
                print('R1 denied: ' + type(error).__name__ + ': ' + str(error)[:300], flush=True)
            if conn:
                try:
                    conn.sendall((json.dumps(result) + '\n').encode())
                except OSError:
                    pass
                finally:
                    conn.close()
