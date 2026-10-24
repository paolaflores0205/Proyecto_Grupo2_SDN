# Respaldo privado antes de limpiar el slice

Ejecutar por bloques y comprobar el resultado antes de continuar. Este procedimiento pausa los servicios del proyecto en controller, h3 y h4; no borra archivos, bases ni flujos. Mantener abierta una conexión SSH de gestión y disponer de consola VNRT.

## 1. Preparación e inventario en controller

Desde PowerShell de Windows:

```powershell
ssh -p 5800 ubuntu@203.0.113.10
```

En controller:

```bash
hostname
date -u
python3 --version
ip -br address
ip route
df -h /
free -h
sudo systemctl status sdn-floodlight sdn-r1 sdn-portal sdn-admin sdn-dhcp mysql --no-pager -l
sudo mysql --connect-timeout=5 sdn_g2 -e "SELECT COUNT(*) AS sesiones_vigentes FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);"
```

Esperado: hostname controller, Python 3.11 o posterior, gestión ens3 y servicios del proyecto reconocibles. Comprobar también Python en los demás nodos antes de ejecutar el script. Estado actual no conocido hasta ejecutar. Si hay sesiones de otras personas, coordinar su finalización antes de detener servicios. No matar sesiones para hacer esta copia. Si MySQL falla, no pasar a limpieza: hay que conseguir primero un dump válido.

En sw1/sw2/sw3, antes de cambiar nada:

```bash
hostname
ip -br address
sudo ovs-vsctl show
sudo ovs-ofctl -O OpenFlow13 show "$(hostname)"
```

Los bridges deben corresponder con los nodos. El script exige hostname correcto. Si difiere del alias, revisar el inventario y adaptar el script conscientemente; no omitir la comprobación.

## 2. Copiar la herramienta a los ocho nodos

En PowerShell, cambiar al directorio de la guía y ejecutar:

```powershell
Set-Location -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldo_y_retorno_VNRT_20261024'
$vnrtPorts = [ordered]@{controller=5800; sw1=5801; sw2=5802; sw3=5803; h1=5811; h2=5812; h3=5813; h4=5814}
foreach ($vnrtNode in $vnrtPorts.Keys) {
    scp -P $vnrtPorts[$vnrtNode] '.\scripts\respaldar_nodo.py' 'ubuntu@203.0.113.10:/home/ubuntu/respaldar_nodo.py'
    if ($LASTEXITCODE -ne 0) { throw "Falló la copia a $vnrtNode; detenerse." }
}
```

Pide contraseña SSH en cada conexión si no tienes claves configuradas. No guardarla en scripts ni publicarla. Verificar huellas si SSH las solicita; no desactivar la comprobación ni aceptar un cambio inesperado sin contrastarlo con VNRT.

## 3. Ejecutar cada respaldo en su nodo

Entrar por SSH al nodo correcto usando su puerto. No pegar los ocho comandos en controller.

| Nodo | Puerto SSH | Comando dentro del nodo |
|---|---:|---|
| controller | 5800 | `sudo python3 ~/respaldar_nodo.py --node controller --quiesce` |
| h3 | 5813 | `sudo python3 ~/respaldar_nodo.py --node h3 --quiesce` |
| h4 | 5814 | `sudo python3 ~/respaldar_nodo.py --node h4 --quiesce` |
| sw1 | 5801 | `sudo python3 ~/respaldar_nodo.py --node sw1` |
| sw2 | 5802 | `sudo python3 ~/respaldar_nodo.py --node sw2` |
| sw3 | 5803 | `sudo python3 ~/respaldar_nodo.py --node sw3` |
| h1 | 5811 | `sudo python3 ~/respaldar_nodo.py --node h1` |
| h2 | 5812 | `sudo python3 ~/respaldar_nodo.py --node h2` |

Ejemplo para h3 desde Windows: `ssh -p 5813 ubuntu@203.0.113.10`; luego el comando de h3.

Orden recomendado: controller, h3, h4, switches y clientes. Finalizar antes cualquier medición en clientes. No reiniciar VM a mitad de este proceso: los servicios aún no están deshabilitados.

**Ruta rápida acordada por chat para controller con 477 MiB libres:** usar `sudo python3 ~/respaldar_nodo.py --node controller --quiesce --project-only`. Este modo conserva la instalación activa `/opt/sdn-floodlight`, configuración y dump SQL, y `/home/ubuntu/sdn-r1r2`, pero excluye las copias históricas Floodlight de `/root` y `/home/ubuntu`. El control de espacio sigue siendo obligatorio y puede detener el script antes de pausar servicios. Las copias históricas excluidas no deben borrarse como si ya se hubieran respaldado; revisarlas o copiarlas aparte antes de retirarlas. El inventario registra el alcance elegido.

La salida válida tiene este formato, con fecha real distinta:

```text
RESPALDO PRIVADO: /home/ubuntu/respaldos-vnrt-20261024/controller-FECHA.tar.gz
SHA256: ...
Verificación interna correcta. Copiar archivo y .sha256 fuera del slice.
```

En los nodos con `--quiesce`, los servicios sdn-* quedan detenidos, no deshabilitados. MySQL sigue funcionando. El script se detiene si no hay espacio conservador suficiente, falta la base o falla la copia. En caso de error posterior a la pausa, algunos servicios pueden quedar detenidos; no asumir que volvió al estado anterior.

## 4. Qué recoge el archivo

- Código real y recursos bajo `/opt/sdn-*`, incluidos JAR y configuración de logs.
- Configuración del proyecto, TLS y secretos en `/etc/sdn-*`; datos privados bajo `/var/lib/sdn-g2`.
- Configuración Netplan, Kea, MySQL, OVS y unidades sdn-* con sus drop-ins.
- Inventario de interfaces/rutas, puertos OVS, DPID, controladores, flows, groups y meters; paquetes, Java y estados de servicios.
- Scripts de medición y evidencias con nombres `medir_r1*` y `evidencias-r1*` de `/home/ubuntu`.
- Respaldos históricos `sdn-*` de `/var/backups` y Floodlight histórico de `/root` si existen.
- En controller: dump lógico de `sdn_g2`, cuentas SQL de la aplicación y sus grants. **No se copia el directorio físico de MySQL en funcionamiento.**

No recoge toda la VM, todas las cuentas del sistema, cualquier archivo arbitrario fuera de esas rutas ni repositorios de otros trabajos. No copia ~/.ssh. Si alguien añadió un archivo, virtualenv, certificado o servicio fuera de esas rutas, incorporarlo expresamente antes de limpiar. El inventario de unidades permite revisar rutas ExecStart y EnvironmentFile.

El archivo contiene información sensible. Sus permisos Linux son 0600 y el directorio 0700. En Windows guardarlo en una carpeta privada de tu usuario/disco protegido; copiarlo a un pendrive o nube solo si están protegidos. No mandarlo al chat ni al repositorio.

## 5. Descargar a Windows fuera de cualquier repositorio

En PowerShell:

```powershell
$privateBackupPath = 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldos_privados_VNRT\campana_20261024'
New-Item -ItemType Directory -Force -Path $privateBackupPath | Out-Null
$vnrtPorts = [ordered]@{controller=5800; sw1=5801; sw2=5802; sw3=5803; h1=5811; h2=5812; h3=5813; h4=5814}
foreach ($vnrtNode in $vnrtPorts.Keys) {
    scp -P $vnrtPorts[$vnrtNode] 'ubuntu@203.0.113.10:/home/ubuntu/respaldos-vnrt-20261024/*.tar.gz*' $privateBackupPath
    if ($LASTEXITCODE -ne 0) { throw "Falló descarga de $vnrtNode; no limpiar." }
}
```

No debe haber `.partial`. Si repetiste un respaldo, separar las campañas: la verificación exige un archivo por nodo y no elige silenciosamente el más reciente.

## 6. Comprobar los ocho archivos

En PowerShell, con el Python instalado en esta computadora:

```powershell
& 'C:\Users\Usuario\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldo_y_retorno_VNRT_20261024\scripts\verificar_respaldos.py' 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldos_privados_VNRT\campana_20261024'
if ($LASTEXITCODE -ne 0) { throw 'No hay respaldo completo verificado; no limpiar.' }
```

Esperado: ocho líneas OK y `8/8 nodos verificados`. Se comprueba hash del archivo, hashes de contenidos y componentes esenciales del controller sin mostrar secretos ni extraer archivos.

Guardar una segunda copia privada fuera del slice y, de ser posible, fuera del mismo disco. Ejecutar el verificador sobre esa segunda carpeta también. Conservar `VERIFICACION_LOCAL.json` junto a los respaldos; es privado y no reemplaza un ensayo de restauración.

**Todavía no borrar nada del slice.** Primero exportar código revisable con la guía 03. Para pasar al laboratorio, seguir la guía 04. Si el verificador falla por una ruta distinta, revisar el despliegue real; no eliminar requisitos solo para obtener un OK.
