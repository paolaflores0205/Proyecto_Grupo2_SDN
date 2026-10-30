"""SSH configurable; rechaza hosts desconocidos y no guarda contraseñas."""
import json,os,pathlib,shlex
import paramiko
CONFIG_PATH=pathlib.Path(os.environ.get('VNRT_TEST_CONFIG','config.local.json'))
def config():return json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
OUT=pathlib.Path(os.environ.get('VNRT_TEST_OUTPUT','resultados-locales'))
def connect(name):
 cfg=config();node=cfg['ssh']['nodes'][name];client=paramiko.SSHClient()
 client.load_system_host_keys()
 if cfg['ssh'].get('known_hosts'):client.load_host_keys(str(pathlib.Path(cfg['ssh']['known_hosts']).expanduser()))
 client.set_missing_host_key_policy(paramiko.RejectPolicy())
 client.connect(node['host'],port=node['port'],username=node.get('user','ubuntu'),password=os.environ.get('VNRT_SSH_PASSWORD'),key_filename=cfg['ssh'].get('key_filename'),timeout=8,banner_timeout=8,auth_timeout=8)
 return client
def command(client,text,sudo=False):
 inp,out,err=client.exec_command('sudo -S -p "" sh -c '+shlex.quote(text) if sudo else text,timeout=35)
 if sudo:inp.write(os.environ['VNRT_SUDO_PASSWORD']+'\n');inp.flush()
 inp.channel.shutdown_write()
 stdout=out.read().decode(errors='replace');stderr=err.read().decode(errors='replace')
 return dict(code=out.channel.recv_exit_status(),stdout=stdout,stderr=stderr)
