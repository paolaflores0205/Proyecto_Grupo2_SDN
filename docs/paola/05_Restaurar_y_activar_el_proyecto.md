# Restaurar y activar R1 R2 después de Lab5

Este procedimiento distingue pausar de reinstalar. El caso normal recomendado conserva archivos y MySQL, detiene el proyecto para Lab5 y luego lo reactiva. Si se borró o reinstaló una VM, la recuperación requiere además paquetes, cuentas y archivos privados: no se resuelve con git pull.

Ejecutar después de completar la experiencia de Lab5, no al terminar solo el previo si debe permanecer en estado reset. Mantener consola VNRT disponible y comprobar huellas SSH. Si cambiaron MAC, DPID, interfaces o IP, no restaurar la topología vieja a ciegas.

## 1. Retirar el control de ONOS

En controller:

```bash
sudo docker ps -a
```

Si el reset de Lab5 ya eliminó el contenedor, no hay que repetirlo. Si aún existe un contenedor llamado onos de ese laboratorio y ya se pueden retirar sus resultados:

```bash
sudo docker stop onos
```

No hace falta borrar la imagen para volver al proyecto. Si el comando Docker no existe porque no se instaló, continuar con comprobación de puertos. Verificar que 6653 esté libre:

```bash
sudo ss -lntp | grep -E ':(6653|8181) ' || true
```

En cada switch, sin ONOS ni Floodlight activos, desconectar el controlador y limpiar reglas residuales como en la guía 04. Conservar los bridges y sus puertos.

## 2. Comprobar qué se conservó

En controller:

```bash
sudo test -f /opt/sdn-portal-paso4/vnrt_avz7_adapter.py && echo ADAPTADOR_PRESENTE
sudo test -f /opt/sdn-floodlight/floodlight.jar && echo JAR_PRESENTE
sudo test -f /etc/sdn-portal-paso4/config.json && echo CONFIG_PORTAL_PRESENTE
sudo test -f /etc/sdn-admin-paso7/config.json && echo CONFIG_DTI_PRESENTE
sudo systemctl cat sdn-floodlight
java -version
sudo systemctl start mysql
sudo mysql --connect-timeout=5 -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name='sdn_g2';"
```

No mostrar los config.json. Esperado: archivos presentes, unidad con su drop-in de logs, Java 8 y base sdn_g2 presente. Revisar puertos y paths reales de ExecStart. Si faltan componentes, usar la sección 7 antes de activar servicios. Si Java cambió, comparar `java_path` y versión en el inventario; no elegir una alternativa sin comprobar cuál conserva Floodlight 1.2.

En h3/h4 comprobar sus unidades y carpetas /opt/sdn-lms-paso3 y /opt/sdn-notas-paso6. En h1/h2 comprobar /etc/sdn-g2/topology.json, trust.pem y smoke_test.py.

## 3. Reestablecer OpenFlow hacia Floodlight

En cada switch, comprobar primero bridge, DPID, puertos y que ens3 no pertenece al bridge:

```bash
hostname
sudo ovs-vsctl show
sudo ovs-ofctl -O OpenFlow13 show "$(hostname)"
ip -br address show ens3
```

Comparar con `metadata/inventory.json` privado del mismo nodo. Si coincide la topología original, ejecutar en cada switch:

```bash
sw=$(hostname)
case "$sw" in sw1|sw2|sw3) ;; *) echo 'Nodo incorrecto'; exit 1;; esac
sudo ovs-vsctl set bridge "$sw" protocols=OpenFlow13
sudo ovs-vsctl set-fail-mode "$sw" secure
sudo ovs-vsctl set-controller "$sw" tcp:198.51.100.10:6653
sudo ovs-vsctl get-controller "$sw"
```

Se espera el target tcp:198.51.100.10:6653. Todavía puede aparecer desconectado hasta iniciar Floodlight. La IP es la de gestión del controller, no el endpoint externo 203.0.113.10. No modificar DPID/ofport si el Lab5 los conservó. Si no coinciden, detenerse y comparar los inventarios en lugar de adivinarlos.

## 4. Arrancar servicios en orden

En h3:

```bash
sudo systemctl enable --now sdn-lms
```

En h4:

```bash
sudo systemctl enable --now sdn-notas sdn-recurso-administrativo
```

En controller:

```bash
sudo systemctl daemon-reload
sudo systemctl start mysql
sudo systemctl enable --now sdn-floodlight
sudo systemctl status sdn-floodlight --no-pager -l
```

Floodlight tiene un ExecStartPost que espera los tres switches e instala/verifica el catálogo base; puede tardar hasta alrededor de un minuto. Si falla, no arrancar todo lo demás ni repetir bootstrap sin diagnóstico. Revisar `sudo journalctl -u sdn-floodlight -n 80 --no-pager` en terminal privada. Esperado: active y tres switches disponibles.

Con Floodlight activo:

```bash
sudo systemctl enable --now sdn-r1 sdn-dhcp
sudo systemctl enable --now sdn-portal sdn-admin
sudo systemctl status sdn-r1 sdn-dhcp sdn-portal sdn-admin --no-pager -l
```

Si Kea informa puerto 67 ocupado, investigar un segundo DHCP; no arrancar dos servidores. La unidad genérica `kea-dhcp4-server` estaba enmascarada por nuestro instalador. Comprobar su estado con `systemctl is-enabled kea-dhcp4-server` y comparar con el respaldo; el servicio utilizado es sdn-dhcp.

Los enable anteriores corresponden a la instalación que estaba habilitada en nuestras pruebas. Si el inventario previo dice disabled para un servicio, respetar ese estado y usar start en lugar de enable para esa unidad.

## 5. Devolver h1/h2 al DHCP del proyecto

Hacerlo después de iniciar sdn-dhcp y tener el catálogo base. En cada cliente usar el directorio exacto que imprimió `datos_cliente_lab5.py --lab-static`, no el de otro cliente:

```bash
sudo python3 ~/datos_cliente_lab5.py --restore /var/backups/sdn-lab5-data-h1-FECHA_REAL
```

En h2 reemplazar por su directorio h2. `FECHA_REAL` es un marcador: no pegarlo literalmente. El programa valida nodo, archivo y cambios ajenos a ens4. Luego:

```bash
sudo networkctl renew ens4
ip -br address show ens3
ip -br address show ens4
ip route
```

Esperado: gestión conservada, h1=192.0.2.1/24 y h2=192.0.2.2/24 por reserva DHCP. La concesión puede tardar unos segundos. Si no se usó la herramienta y ens4 nunca cambió, no ejecutar restore; solo comprobar o renovar DHCP. Si se perdió el respaldo específico del cambio, recuperar el YAML original del respaldo privado y revisar antes de aplicarlo.

En controller, una vez que ambos tengan IP:

```bash
sudo python3 /opt/sdn-portal-paso4/portable_observe.py
```

Solicita observación ARP limitada a h1/h2. No vacía vecinos de gestión.

## 6. Validar antes de retomar pruebas

En controller:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/wm/core/controller/switches/json
sudo python3 /opt/sdn-portal-paso4/vnrt_avz7_red.py verify
sudo mysql --connect-timeout=5 sdn_g2 -e "SELECT COUNT(*) AS sesiones_vigentes FROM sessions WHERE revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6);"
```

Esperado: tres switches, OVS_BASELINE_VERIFIED y normalmente cero sesiones tras los días del laboratorio. Si aparecen sesiones válidas, revisar en lugar de borrarlas. No importar flows de un dump antiguo: el adaptador y bootstrap reconstruyen lo que corresponde al estado actual.

En h1:

```bash
curl --interface ens4 --cacert /etc/sdn-g2/trust.pem --connect-timeout 3 --max-time 5 -sS -o /dev/null -w 'Portal HTTP %{http_code}\n' https://192.0.2.10/
curl --interface ens4 --cacert /etc/sdn-g2/trust.pem --connect-timeout 3 --max-time 5 -sS -o /dev/null -w 'LMS sin sesion HTTP %{http_code}\n' https://192.0.2.3/
python3 /etc/sdn-g2/smoke_test.py --help
```

Portal esperado 200; LMS sin sesión timeout/000 contrastado con reglas. Leer la ayuda del smoke real y ejecutarlo con sus parámetros; no inventar argumentos de otra versión. Usar las credenciales recuperadas privadamente. Debe terminar SMOKE_PASS y después quedar sin sesión ni permisos individuales en tablas 10/20 de sw2. Ejecutar después las pruebas de logout/roles que correspondan y registrar nueva fecha/IDs.

### Túneles para el navegador desde Windows

Cada comando en una ventana PowerShell que permanece abierta:

```powershell
ssh -p 5811 -N -o ExitOnForwardFailure=yes -L 127.0.0.1:19443:192.0.2.10:443 ubuntu@203.0.113.10
```

Portal h1: https://127.0.0.1:19443/.

```powershell
ssh -p 5812 -N -o ExitOnForwardFailure=yes -L 127.0.0.1:20443:192.0.2.10:443 ubuntu@203.0.113.10
```

Portal h2: https://127.0.0.1:20443/. Usar otro perfil o InPrivate para separar cookies; puertos distintos por sí solos no las separan.

```powershell
ssh -p 5800 -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18443:198.51.100.10:8443 ubuntu@203.0.113.10
```

DTI: https://127.0.0.1:18443/dashboard. Los certificados del laboratorio pueden generar advertencia en el navegador por confianza/nombre local; no quitar la validación TLS de curl ni cambiar las CA globales para ocultarla.

## 7. Si faltan archivos o se borró la VM

No ejecutar a ciegas el instalador del 14/10: crea base y secretos nuevos y su adaptador histórico no contiene todas las correcciones del 22/10. Tampoco copiar solo el adaptador ni hacer git pull esperando recuperar claves y datos.

### Recuperar archivos en la misma VM

1. Verificar de nuevo el archivo privado y su .sha256 en Windows; copiar únicamente el respaldo del nodo correspondiente por scp. Ejemplo, con nombre real:

```powershell
scp -P 5800 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldos_privados_VNRT\campana_20261024\controller-FECHA_REAL.tar.gz' 'ubuntu@203.0.113.10:/home/ubuntu/'
```

2. En la VM, crear un directorio nuevo privado para inspección y extraer allí, no sobre `/`:

```bash
sudo install -d -m 0700 /var/tmp/recuperacion-sdn-20261024
sudo tar -xzpf /home/ubuntu/controller-FECHA_REAL.tar.gz -C /var/tmp/recuperacion-sdn-20261024
```

Si el directorio ya existe, usar uno nuevo y revisar por qué; no mezclar campañas. No listar por pantalla config.json, SQL ni claves. Bajo `filesystem/` están las rutas originales, y en `metadata/` están SQL e inventario.

3. Con todos los servicios del proyecto detenidos, comparar las rutas faltantes. Ejemplo si SOLO se retiró `/opt/sdn-floodlight` y el usuario ubuntu conserva su UID/GID original:

```bash
sudo test ! -e /opt/sdn-floodlight && sudo cp -a /var/tmp/recuperacion-sdn-20261024/filesystem/opt/sdn-floodlight /opt/
```

Si la carpeta existe, ese comando no copia: comparar archivos, no fusionar indiscriminadamente. Recuperar unidades/drop-ins faltantes de la misma manera, preservando modos/propietario, y ejecutar daemon-reload. Revisar que el Java de ExecStart y las cuentas sigan existiendo.

No restaurar automáticamente `/etc/openvswitch/conf.db` sobre un OVS en ejecución, ni todo `/etc/netplan` o `/etc/systemd/system`. La topología y gestión actuales podrían ser distintas; para switches usar los valores inventariados mediante ovs-vsctl.

### Recuperar MySQL solo si la base falta

En la misma VM, si MySQL y sdn_g2 siguen presentes, no importar nada: conservar sus datos. Si la base se perdió, comparar versión MySQL, instalar dependencias y recuperar el dump lógico en una instancia revisada. Las aplicaciones deben estar detenidas.

```bash
sudo mysql --connect-timeout=5 -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name='sdn_g2'; SELECT User,Host FROM mysql.user WHERE User IN ('sdn_portal','sdn_dti');"
```

Solo si la base y las cuentas esperadas están ausentes (o se ha preparado explícitamente su migración), importar desde staging privado:

```bash
sudo sh -c 'mysql --protocol=socket < /var/tmp/recuperacion-sdn-20261024/metadata/sdn_g2.sql'
sudo sh -c 'mysql --protocol=socket < /var/tmp/recuperacion-sdn-20261024/metadata/mysql-app-users.sql'
```

Los config.json deben corresponder a esas cuentas SQL recuperadas, no a secretos nuevos de otra instalación. Si las cuentas ya existen, el segundo archivo puede fallar con CREATE USER; no usar --force ni DROP USER para hacerlo pasar. Revisar grants y credenciales conjuntamente. No recuperar el directorio físico `/var/lib/mysql` desde otra versión.

Sesiones antiguas normalmente estarán vencidas. Si se requiere invalidarlas, hacerlo como operación revisada y registrar la decisión, sin cambiar el reloj del sistema ni presentar una sesión histórica como una nueva prueba.

### VM nueva o slice recreado

Requiere inventario nuevo completo y probablemente adaptar MAC, DPID, ofport y certificados. Restaurar paquetes compatibles según el inventario (Python/Flask/Gunicorn/PyMySQL/MySQL/Kea/OVS y Java 8), crear la cuenta/grupo sdnportal si falta, revisar UID/GID al recuperar propietarios y comprobar todos los EnvironmentFile/ExecStart.

No se ofrece un comando universal para sobrescribir una VM nueva: su inventario aún no existe. El backup conserva los datos para hacerlo; una restauración integral nueva debe prepararse y comprobarse en ese entorno. Conservar los originales hasta terminar smoke, revocación, vencimiento, aislamiento y acceso de gestión.
