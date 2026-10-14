# Guía de despliegue para el compañero y su Codex

## 0. Instrucción que puedes pasarle a Codex

> Quiero desplegar este paquete R1/R2 en mi propio VNRT. Lee completamente README.md, GUIA_CODEX.md, VALIDACION.md y los scripts antes de ejecutar cambios. Primero inventaría mis VMs y enlaces por SSH, sin modificar nada; no uses las IP/MAC/DPID/puertos del ejemplo como si fueran míos. Presenta la correspondencia de interfaces y protege la red administrativa/SSH. Confirma conmigo que el laboratorio de destino se puede reemplazar y que tengo consola VNRT. Completa mi topology.json, genera un directorio nuevo con prepare.py y despliega por roles en el orden indicado. No ejecutes scripts históricos independientemente, no implementes R5 ni modifiques el gateway. No muestres contraseñas, cookies o claves privadas en tus herramientas, registros o respuesta. Si hay una instalación previa o una topología diferente, detente y propón una migración antes de sobrescribir. Verifica reglas efectivas y pruebas por rol; entrega evidencia y distingue lo probado de lo pendiente.

Las instrucciones de este documento forman parte de la guía técnica. El Codex del compañero debe seguir la autorización que le dé su usuario; la guía no autoriza por sí sola a borrar instalaciones, credenciales o datos.

## 1. Qué se despliega y qué no

La solución conceptual está orientada al campus PUCP; este paquete es su **validación funcional en VNRT**, no una instalación institucional de producción. Topología lógica mínima:

```
h1, h2 -- sw2 (acceso) -- sw1 (core) -- sw3 (servicios) -- h3 / h4
                            |
                         controller
```

Las conexiones anteriores son Ethernet del plano de datos. Separadamente, cada VM conserva su interfaz administrativa. sw1/sw2/sw3 se conectan desde esa red al controller mediante OpenFlow TCP/6653. El SSH del VNRT, aunque use puertos de entrada 5800/5801/etc., es administración: **esos puertos NO se usan en las reglas del tráfico académico**.

| Nodo lógico | Componentes | Dirección/interfaz |
|---|---|---|
| controller | Floodlight Java, aplicación Python/portal, adaptador, consola DTI, MySQL, Kea | Dos redes: administrativa y datos |
| sw1 | OVS core y tránsito común acotado | Puertos hacia controller, sw2, sw3 |
| sw2 | OVS acceso y reglas individuales | Puertos hacia sw1, h1, h2 |
| sw3 | OVS servicios y reglas individuales | Puertos hacia sw1, h3, h4 |
| h1/h2 | Clientes, IP por reserva DHCP | Una MAC de datos conocida por cliente |
| h3 | Recurso ficticio LMS HTTPS/443 | IP estática de datos |
| h4 | Recursos ficticios Notas HTTPS/443 y Administración HTTPS/8443 | IP estática de datos |

La consola **DTI del controller:8443** administra cuentas, permisos y sesiones. No es el **recurso administrativo h4:8443**: se alojan en máquinas/redes distintas.

No hay VLAN/802.1Q, metadata OpenFlow, autenticación por MAC, integración de cuentas institucionales, réplica MySQL, HA de controlador, Suricata, R5 ni modificaciones al gateway. No se añaden Wi-Fi ni reglas que permitan Internet. Kea no anuncia router ni DNS: se accede a las IP explícitas. El portal presenta un login HTTPS; no se debe prometer redirección transparente universal de HTTPS.

## 2. Inventario obligatorio, SOLO lectura

Solicita al dueño endpoint SSH, usuario, puerto de cada VM y acceso a consola VNRT. Verifica huellas SSH; no desactives su comprobación global ni sustituyas silenciosamente una huella cambiada. No guardes contraseñas en topology.json.

En cada VM:

```bash
hostname
ip -br address
ip -j address
ip -j route
ip route get DIRECCION_DEL_CLIENTE_SSH
systemctl is-active systemd-networkd
sudo ls -l /etc/netplan
sudo ss -lntup
```

Lee Netplan sin publicar contenidos sensibles. Identifica la interfaz que sostiene SSH y la ruta de gestión. En cada switch:

```bash
sudo ovs-vsctl show
sudo ovs-vsctl list-br
sudo ovs-vsctl list-ports NOMBRE_BRIDGE
sudo ovs-vsctl get bridge NOMBRE_BRIDGE datapath_id
sudo ovs-ofctl -O OpenFlow13 show NOMBRE_BRIDGE
sudo ovs-ofctl -O OpenFlow13 dump-flows NOMBRE_BRIDGE
```

La salida `ovs-ofctl show` relaciona **ofport con interfaz**. El número de interfaz `ens5` NO implica que su ofport sea 5. Correlaciona los enlaces con el diagrama del navegador VNRT y, si es necesario, información LLDP/capturas pasivas. No supongas enlaces por la posición del dibujo. Confirma todas las MAC de datos, no las de administración.

Antes de modificar: comprueba si existen `/opt/sdn-*`, servicios `sdn-*.service`, base `sdn_g2`, procesos Floodlight/Java, servidor DHCP o recursos escuchando en 443/8443. Comprueba almacenamiento libre (`df -h /`, `sudo du -xhd1 /opt /var`), RAM (`free -h`), versión Ubuntu (`cat /etc/os-release`), Java (`java -version`) y acceso a repositorios APT. Reserva espacio para JAR, instalación MySQL/Java y respaldos; no uses el espacio mínimo de ZIP como requerimiento completo.

Este instalador está pensado para Ubuntu con **systemd-networkd + Netplan** y usuario `ubuntu`. La referencia original usa Ubuntu 24/Python 3.12/MySQL 8. Otros sistemas/versiones necesitan revisar dependencias y Java/Floodlight antes de aplicar cambios. No instala MySQL ni servidores web en Windows: tu computadora solo genera/transfiere archivos y abre túneles.

## 3. Preparar configuración e integridad

`SHA256SUMS.json` contiene SHA-256 relativo de cada archivo distribuido. Codex debe comprobar esos hashes antes de generar. El manifiesto detecta alteraciones accidentales; no es una firma del autor.

Copia `topology.example.json` a `topology.json` y cambia:

| Campo | Significado |
|---|---|
| `ssh.host`, `ssh.user`, `ssh.ports` | Acceso externo a VMs; información para el compañero/Codex, no para los flows |
| `data_cidr` | Subred IPv4 de datos, sin solaparse con gestión |
| `controller_management_ip` | IP administrativa donde escucha OpenFlow; no endpoint NAT de SSH |
| `nodes.*.management_interface` | NIC que NO debe tocarse |
| `nodes.*.data_interface`, `ip`, `mac` | NIC de datos, IP propia del nuevo entorno y MAC observada |
| `nodes.*.switch`, `port` | Switch lógico y ofport donde está conectado ese nodo |
| `switches.*.bridge`, `dpid` | Bridge y DPID observado; no inventar DPID de un bridge existente |
| `switches.*.ports` | Mapa `ofport: interfaz Linux`, exclusivamente datos |
| `switches.*.links` | Vecino lógico y ofport local que conecta a ese vecino |
| `confirmed_after_inventory` | `true` únicamente después de verificar todo lo anterior |

Los ejemplos conservan las IP anteriores de Matthew para ilustrar el diseño. **Las interfaces y todos los demás valores deben verificarse**, incluso si coinciden. Los alias `sw1`, `sw2`, etc. designan funciones; el hostname real de la VM puede ser distinto. El instalador exige que cada switch tenga los tres puertos de este diseño, sin enlaces extra. No admite h4 ausente, más clientes ni árboles arbitrarios automáticamente.

Ejecuta en la computadora del compañero (Python estándar, sin Flask/MySQL necesarios para generar):

```bash
python prepare.py topology.json --out generated-vnrt
```

Se rechaza configuración no confirmada, IP/MAC/DPID duplicadas, colisiones de puertos y NIC administrativa incluida en OVS. El directorio de salida debe ser nuevo. No se conecta a VMs. Revisa `generated-vnrt/catalog_base.json` y `catalog_examples.json`; el segundo solo es una muestra offline, **NO una sesión real ni un archivo para instalar permisos manualmente**.

`generated-vnrt/source/vnrt_avz7_red.py` y `vnrt_flujos_https_paso3.py` son versiones ajustadas. Las plantillas `portable_flows.py` y `portable_context.py` no se ejecutan directamente para desplegar. Nunca copies solamente main.py: esta implementación depende de varios módulos, HTML, CSS, SQL, JAR y unidades systemd.

## 4. Transferencia y orden de instalación

Por ejemplo, adapta nombres/puertos:

```bash
scp -P PUERTO -r generated-vnrt ubuntu@HOST_VNRT:/home/ubuntu/
ssh -p PUERTO ubuntu@HOST_VNRT
```

SFTP también sirve. Se puede transferir todo el directorio generado a las ocho VMs. El JAR solo es necesario en controller; si falta espacio, Codex puede omitir `vendor/` en las otras VMs después de comprobar dependencias. No muevas claves privadas entre máquinas. No envíes archivos privados recién generados a GitHub o al grupo completo.

Dentro de cada VM, desde `/home/ubuntu/generated-vnrt`, ejecutar **con su rol correcto**, nunca todos los roles en controller:

```bash
sudo python3 install_node.py sw1 --confirm-clean-lab
```

Orden:

1. sw1, sw2, sw3: configurar OVS/puertos/OpenFlow/secure, conservando gestión. Sustituir `sw1` por el rol de cada VM.
2. h3, h4: configurar IP estática de datos y crear los recursos HTTPS/certificados.
3. controller: IP de datos, MySQL vacía, cuentas y secretos nuevos, Floodlight, adaptador, portal, DTI y Kea. Los tres switches deben estar presentes para que bootstrap termine.
4. h1, h2: DHCP solo en su NIC de datos y script de pruebas. Esperar la reserva y verificar la IP resultante.

El indicador `--confirm-clean-lab` autoriza reemplazar la configuración de **esos bridges de laboratorio**. Floodlight configura `clearTablesOnInitialHandshakeAsMaster` y `clearTablesOnEachTransitionToMaster`: al conectar limpiará sus tablas. Esto no preserva reglas de otro laboratorio/proyecto en los mismos bridges. El instalador no borra directorios ni bases previas: si encuentra una instalación SDN propia, se detiene y exige migración revisada.

**No ejecutes con `python -O`: las comprobaciones usan assert.** No reejecutes ciegamente después de un error parcial. Captura el mensaje sin secretos y revisa qué llegó a instalarse; el rechazo a instalaciones previas es deliberado, no un fallo que deba omitirse.

Se genera respaldo local en `/var/backups/sdn-portable-ROL-FECHA/` (Netplan, unidades, configuración OVS, inventario IP/rutas). Antes de iniciar también guarda copia del proyecto existente y snapshot/exportación VNRT si la plataforma lo permite. El respaldo del instalador **no es una imagen completa ni un dump de datos MySQL anteriores**.

## 5. Cómo funcionan los componentes y archivos

| Archivo | Función / relación con módulos |
|---|---|
| `vnrt_portal_paso4.py` | Base Flask, conexión MySQL, hashes de contraseña/token, CSRF y cookie segura |
| `vnrt_portal_paso5.py` | Login/logout y sesión por terminal; hereda la base, no se instala aparte |
| `vnrt_avz7_portal.py` | Entrada final Gunicorn del portal: identidad vigente, binding observado y panel de tres recursos; M01/M02 |
| `vnrt_r1_paso5.py` | Compatibilidad mínima: DB, socket Unix y bucle daemon; no contiene los permisos fijos antiguos |
| `vnrt_avz7_adapter.py` | M02/M03 y enlace con M09: reconcilia sesión/rol/permiso, verifica ubicación y reglas, retira/recrea permisos temporales |
| `vnrt_avz7_red.py` generado | Catálogo base y cuatro reglas por sesión–recurso, normalización y verificación real de OVS |
| `vnrt_flujos_https_paso3.py` generado | Contexto dinámico (HOSTS/DPID/ADJ), API Floodlight y camino; no es el antiguo script de concesión fija |
| `vnrt_admin_paso7.py`, `vnrt_avz7_admin.py` | M07: login DTI independiente, revisión/revocación de sesiones, cambios de permisos y auditoría |
| `vnrt_lms_https_paso3.py` | Servidor HTTPS de lectura ficticio en h3 |
| `vnrt_notas_https_paso6.py` | Servidor HTTPS de lectura ficticio en h4:443 |
| `vnrt_recurso_administrativo.py` | Recurso ficticio en h4:8443, NO consola DTI |
| `portable_observe.py` | ARP dirigido de datos para registrar h1/h2 en Devices; sin vaciar vecinos/rutas globales |
| HTML/CSS | Pantallas de portal/DTI; no son recursos institucionales reales |
| `floodlight.properties` | Dirección OpenFlow, REST loopback, módulos y forwarding automático deshabilitado |
| `schema.sql` | M10: estructura final vacía (cuentas, roles, recursos, permisos, sesiones, reglas y auditoría) |

Los sufijos paso3/paso4/paso5/paso7 se conservan para respetar las importaciones del código probado. **No representan la secuencia de despliegue actual** ni autorizan ejecutar scripts de restauración antiguos. M08/descubrimiento se apoya en Floodlight Devices/Topology; M09 usa la API northbound. Java ejecuta Floodlight; Python ejecuta la aplicación: son procesos diferentes, no dos implementaciones del controlador.

## 6. Enlaces, protocolos y límites de las reglas

| Conexión | Protocolo / puerto | Uso |
|---|---|---|
| Terminal → Kea en controller | Ethernet/IPv4 UDP 68→67; respuesta 67→68 | Reserva MAC–IP; solo h1/h2 conocidos |
| Terminal → portal controller | HTTPS TCP/443, datos | GET login / POST login / panel / POST logout |
| DTI → controller | HTTPS TCP/8443, gestión | Autenticación independiente y consola administrativa |
| Aplicación/adaptador/DTI → MySQL | TCP/3306, 127.0.0.1 | Consultas/estado/auditoría con cuentas SQL restringidas |
| Portal/DTI → adaptador | Socket Unix `/run/sdn-r1/policy.sock` | Sincronización local de permisos; no es un cable ni REST pública |
| Adaptador → Floodlight | HTTP JSON TCP/8080, 127.0.0.1 | API Devices, Topology, staticflowpusher y estadísticas reales |
| Floodlight → switches | OpenFlow 1.3 TCP/6653, gestión | Flow-Mod, estadísticas y eventos |
| Switches entre sí / hosts | Ethernet; ARP 0x0806, IPv4 0x0800 | Datos y resolución de vecinos |
| Descubrimiento switches | LLDP 0x88cc / BDDP 0x8942 | Copia al controlador en enlaces inter-switch |
| Usuario autorizado → recurso | HTTPS TCP/443 o TCP/8443 | Ida y retorno por switches, NO por el portal como proxy |

OpenFlow está configurado TCP sin TLS en el laboratorio; no afirmar cifrado del canal de control. La API REST y MySQL quedan en loopback, no accesibles directamente desde clientes. No abras 8080/3306 a toda la red para facilitar el despliegue.

### Reglas finales, no las retiradas

El catálogo base contiene **41 reglas propias**: sw1=19, sw2=15, sw3=7. Puede verse además la regla interna table-miss de Floodlight en cada switch (44 entradas totales de referencia); distinguir entradas propias e internas. El JSON generado es la definición exacta de match/acciones para las IP/puertos del compañero.

| Familia | Prioridad | Match y acción | Tiempo |
|---|---:|---|---|
| Denegación por defecto | 50 | Match general; sin acciones (drop) | Permanente |
| ARP | 300 | EtherType ARP y MAC/puerto conocidos; fanout acotado según catálogo, algunos envían copia al controller | Permanente |
| Tránsito común servicios sw1 | 350 | IP/subred destino/origen y puerto de servicio; output acotado, solo core | Permanente |
| Portal y DHCP | 400 | IP/MAC/puertos correspondientes; ida/retorno | Permanente |
| Permiso sesión–recurso | 500 | Puerto de ingreso, MAC, IP, TCP y puerto del servicio; output concreto | Idle=0, hard≤30 s |
| LLDP/BDDP | 64000 | EtherType y puerto inter-switch; output controller | Permanente |

Cada par **sesión–recurso autorizado** requiere 4 reglas: ida/retorno en sw2 e ida/retorno en sw3. No se multiplica todo el catálogo base por usuario. sw1 comparte tránsito de servicios, pero ello no basta para conceder acceso: los bordes sw2 y sw3 verifican el permiso individual.

El adaptador reconcilia aproximadamente cada 2 s y renueva leases alrededor de cada 10 s por retiro/reinstalación verificados. Usa leases cortos como respaldo ante caída de aplicación; no garantizan revocación instantánea si falla el controlador. Sesión web de 15 min, una identidad activa por terminal, sesiones separadas para distintos dispositivos. IP/MAC/DPID/puerto vinculan la sesión observada, **no sustituyen contraseña ni impiden por sí solos suplantación de MAC**.

Matriz SQL inicial:

| Rol | LMS h3:443 | Notas h4:443 | Administración h4:8443 |
|---|---|---|---|
| estudiante | Permitir | Denegar | Denegar |
| docente | Permitir | Permitir | Denegar |
| administrativo | Denegar | Denegar | Permitir |
| visitante | Denegar | Denegar | Denegar |

Son destinos de red diferentes; las reglas no distinguen rutas URL cifradas dentro de un mismo HTTPS. No se implementan Paideia/Notas reales ni autorización de operaciones académicas internas: son páginas ficticias de lectura para validar R1/R2.

## 7. Credenciales y certificados del nuevo VNRT

El instalador genera contraseñas aleatorias nuevas y hashes scrypt. Archivos privados **solo en controller**, root/0600, bajo `/var/lib/sdn-g2/private/`: `usuarios-prueba.json`, `credenciales-dti.json`. SQL y cookie secrets quedan en `/etc/sdn-portal-paso4/config.json` y `/etc/sdn-admin-paso7/config.json`, root:sdnportal/0640. No devolver estos contenidos en herramientas que registran stdout, no incluirlos en ZIP/GitHub y no reutilizar cuentas universitarias.

El dueño puede leer sus cuentas en una terminal privada y escribir la contraseña en `smoke_test.py` (entrada oculta). Codex no necesita publicarlas para verificar que los archivos existen y tienen permisos correctos. Si automatiza autenticación, debe conservar secretos únicamente en memoria y reportar resultados redactados.

Se generan certificados autofirmados con SAN de la IP adaptada. Recoge **únicamente** los certificados públicos:

- controller `/etc/sdn-portal-paso4/server.crt`;
- controller `/etc/sdn-admin-paso7/server.crt`;
- h3 `/opt/sdn-lms-paso3/server.crt`;
- h4 `/opt/sdn-notas-paso6/server.crt`.

Concatena los PEM públicos en `trust.pem`, usando una herramienta de archivos, y copia a `/etc/sdn-g2/trust.pem` en h1/h2. Las claves `server.key` NO se copian. No reemplaces las CA globales de la VM. Para curl: `--cacert /etc/sdn-g2/trust.pem`. Al cambiar IP hay que regenerar certificados del despliegue; no editar el JSON de una instalación activa y asumir que todo cambiará.

## 8. Comprobaciones después del despliegue

En todas las VMs, compara `ip -j address`/`ip -j route` con el respaldo: IP administrativa y ruta por defecto de gestión deben mantenerse. Abre una segunda conexión SSH antes de cerrar la primera.

En controller:

```bash
sudo systemctl status sdn-floodlight sdn-r1 sdn-portal sdn-admin sdn-dhcp mysql --no-pager
sudo ss -lntup
curl -s http://127.0.0.1:8080/wm/core/controller/switches/json
curl -s http://127.0.0.1:8080/wm/device/
curl -s http://127.0.0.1:8080/wm/topology/links/json
sudo python3 /opt/sdn-portal-paso4/vnrt_avz7_red.py verify
```

Deben aparecer exactamente los tres DPID configurados. Devices debe asociar IP/MAC de h1/h2 con sw2/puerto correcto. Usa `/wm/staticflowpusher/...`, no confundas la ruta con una API de otro build. El bootstrap compara el catálogo con **flujos reales del switch**, no solo con la respuesta HTTP de instalación.

En switches:

```bash
sudo ovs-vsctl get-controller NOMBRE_BRIDGE
sudo ovs-vsctl get-fail-mode NOMBRE_BRIDGE
sudo ovs-ofctl -O OpenFlow13 dump-flows NOMBRE_BRIDGE
```

En h1/h2: verificar reserva DHCP en NIC de datos, ausencia de nueva ruta por defecto de datos y ejecutar:

```bash
python3 /etc/sdn-g2/smoke_test.py
```

Repetir con los cuatro roles en ambos clientes (cerrar sesión entre casos). El script comprueba antes/login/después de logout y los tres destinos. Un timeout aislado no demuestra denegación: primero valida que el mismo servidor responde cuando el rol correcto tiene permiso y contrasta reglas efectivas/counters. El script NO sustituye todos los casos de consistencia.

Pruebas adicionales necesarias: credenciales erróneas; login válido sin permiso; dos dispositivos del mismo usuario y revocación de solo uno desde DTI; cambio de permisos/rol y retiro de accesos; expiración de sesión; caída/reinicio del adaptador y expiración de leases; caída de Floodlight y rechazo de nuevo login. No realizar pruebas de desconexión destructivas sin ventana y autorización del dueño. Guardar resultados sin cookies/tokens.

Para ver en navegador de la computadora, usar túnel SSH **por h1 o h2**: `ssh -p PUERTO_H1 -N -L 9443:IP_PORTAL:443 ubuntu@HOST_VNRT`, y recurso mediante otro puerto local. Así el origen observado del tráfico es el cliente. Un túnel por controller no simula h1 y puede ser rechazado deliberadamente. Certificados emitidos para IP darán aviso si el navegador usa localhost; resolver confianza/nombre en un entorno de laboratorio, no deshabilitar verificación TLS como configuración permanente.

## 9. Fallos, recuperación y límites

- Si faltan DPID, bootstrap puede fallar: revisar interfaces/ofports, IP de gestión y TCP/6653; no sustituir todo por NORMAL.
- Si Devices no conoce IP/MAC/puerto, no conceder login a ciegas. Revisar DHCP, ARP y regla de copia al controller.
- Si falta servicio, revisar `journalctl -u SERVICIO` y puerto correspondiente, redactando identificadores de sesión/cookies antes de compartir.
- Si Netplan contiene match/set-name, renderer diferente, rutas/DNS en NIC de datos o configuración compleja, el script se detiene. Codex debe preparar ajuste puntual revisado; no eliminar YAML adicionales ni tocar ens3 indiscriminadamente.
- Si hay poco espacio, diagnosticar antes de instalar. No borrar MySQL, JAR, paquetes Java/Python, logs o respaldos del compañero automáticamente.
- Una excepción parcial no implica rollback global automático. Detener unidades propias que hayan quedado activas, consultar respaldo y cambios antes de reintentar.

Recuperación: la consola VNRT permite recuperar gestión si falla SSH, **pero no se garantiza conexión ininterrumpida**. El respaldo contiene YAML y configuraciones para restaurar cambios específicos. No extraer `configs.tgz` directamente sobre `/etc` ni restaurar toda la red sin comparar. Detener servicios propios, restaurar solo el archivo Netplan alterado y reconfigurar únicamente la NIC afectada; restaurar bridge/controlador/puertos desde el inventario guardado con autorización. La base creada contiene datos nuevos: respaldarla si se quiere conservar; no ejecutar DROP ni borrar `/opt` como supuesto paso de recuperación. Para volver exactamente al estado inicial conviene snapshot/exportación VNRT anterior al despliegue.

El paquete no contiene tu configuración personalizada de campus ni pruebas de miles de usuarios. La cantidad de reglas es cálculo del diseño; no prueba TCAM física de OVS, throughput, latencia p95 ni capacidad concurrente. Esas mediciones corresponden al avance 8 y deben realizarse/reportarse aparte.

## 10. Procedencia y redistribución

`vendor/floodlight.jar` es una copia del JAR usado en la implementación original. Su hash está en el manifiesto. Se incluyen avisos de dependencias extraídos del JAR y licencia/NOTICE de la distribución Floodlight v1.2 como referencia. Código público de referencia: https://github.com/floodlight/floodlight/tree/v1.2. No se afirma reconstrucción reproducible exacta del JAR ni verificación independiente de toda su cadena de dependencias. Revisar avisos de licencia antes de redistribuirlo fuera del grupo.

El ZIP no contiene claves privadas/certificados del VNRT de Matthew, passwords SQL, passwords DTI, sesiones, dumps de usuarios, túneles, endpoints SSH privados ni scripts personales de restauración. El schema fue exportado **sin datos**. Sus únicos usuarios de demostración se crean con secretos nuevos en el destino.
