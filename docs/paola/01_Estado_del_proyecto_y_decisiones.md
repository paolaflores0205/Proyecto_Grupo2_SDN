# Estado del proyecto R1 y R2 al preparar Lab5

Este registro conserva el trabajo documentado hasta el 22 de octubre. El 24 de octubre no se consultó el estado vivo de las VM. Cambios posteriores de otros integrantes deben inventariarse antes de respaldar o restaurar.

## Objetivo y componentes

R1 autentica usuarios, mantiene una sesión por terminal y vincula IP, MAC, DPID y puerto observado. R2 determina permisos explícitos por recurso. El portal no es un proxy del tráfico: el cliente accede directamente al servidor a través de los switches.

En controller funcionan Floodlight Java, MySQL, portal Flask/Gunicorn, adaptador Python, consola DTI y Kea DHCP. El proyecto usa `sdn-floodlight`, `sdn-r1`, `sdn-portal`, `sdn-admin`, `sdn-dhcp` y `mysql`. h3 usa `sdn-lms`; h4 usa `sdn-notas` y `sdn-recurso-administrativo`. El respaldo descubrirá los nombres realmente instalados.

DTI en controller:8443 es una consola administrativa independiente del recurso Sistema administrativo de h4:8443. Tampoco son equivalentes `dti_demo` y `administrativo_demo`.

## Inventario conocido que debe comprobarse

Endpoint anterior: ubuntu@203.0.113.10. Puertos externos: controller 5800, sw1 5801, sw2 5802, sw3 5803, h1 5811, h2 5812, h3 5813 y h4 5814. Si la plataforma muestra otros, usar el inventario actual.

Gestión: ens3, red 198.51.100.0/24. Controller de gestión: 198.51.100.10. No modificar ens3 ni su ruta de SSH.

| Nodo | Datos | Ubicación conocida |
|---|---|---|
| controller | 192.0.2.10 | sw1 puerto 1 |
| h1 | 192.0.2.1, MAC 02:00:00:00:00:01 | sw2 puerto 2, interfaz local ens5 |
| h2 | 192.0.2.2, MAC 02:00:00:00:00:02 | sw2 puerto 3, interfaz local ens6 |
| h3 LMS | 192.0.2.3:443 | sw3 puerto 2 |
| h4 Notas | 192.0.2.4:443 | sw3 puerto 1 |
| h4 Administración | 192.0.2.4:8443 | mismo servidor h4 |

En h1/h2/h3/h4 la interfaz de datos conocida es ens4. DPID sw1: 00:00:00:00:00:00:00:01; sw2: 00:00:00:00:00:00:00:02; sw3: 00:00:00:00:00:00:00:03.

## Diseño de tablas y protocolos

sw2 usa tabla 0 para clasificación/excepciones, 10 para sesión, 20 para autorización y 30 para reenvío. Metadata 0x1/0x2 distingue h1/h2; no representa roles ni viaja a sw3. En sw3 también hay permisos individuales. El descarte por defecto tiene prioridad 50; identidad 700; permiso 800.

En esta topología: 52 reglas base propias + 2 por sesión habilitada + 4 por permiso terminal–recurso. No equivale al consumo de TCAM, no incluye reglas internas ajenas y no es una fórmula de capacidad de campus.

Portal HTTPS 443; recursos HTTPS 443/8443. MySQL 127.0.0.1:3306; REST Floodlight 127.0.0.1:8080; OpenFlow gestión TCP/6653. Portal y DTI piden sincronización al adaptador mediante `/run/sdn-r1/policy.sock`. No abrir REST/MySQL públicamente. OpenFlow de laboratorio no tiene TLS.

## Cambios aplicados y respaldos conocidos

1. Disco lleno: se recuperó espacio y se redujo logging. Configuración `/opt/sdn-floodlight/logback-vnrt.xml` y drop-in `/etc/systemd/system/sdn-floodlight.service.d/30-logback-vnrt.conf`. No se demostró una causa única del 503 ni se amplió el disco.
2. Renovación: identidad y permisos vigentes se renuevan por POST sin retirarlos primero. Solo se eliminan nombres obsoletos. Reglas de hasta 30 s, renovación aproximada cada 10 s y sesión web de 15 min. Respaldo previo: `/var/backups/sdn-r1-continuidad/20261020T190428Z/`.
3. Coherencia de estado: la actualización global de revocados también pone `network_state='revoked'`; la actualización ACTIVE exige `revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)`. Se observó antes h2 REVOKED/active pese a que OVS ya había retirado permisos. Respaldo previo: `/var/backups/sdn-r1-estado-revocacion/20261022T043715611264Z/`.
4. Instrumentación: scripts de activación, continuidad, logout y concurrencia, resúmenes reproducibles y conservación de fallos.

La última copia local del adaptador es `../Mediciones_R1_G2/vnrt_avz7_adapter_corregido_20261022.py`. No sustituye los demás módulos, HTML, CSS, certificados, SQL ni unidades systemd que hay que recuperar del nodo real.

## Resultados documentados

- Smoke: sin sesión bloqueado, estudiante accede al LMS, logout retira; controles de Notas/Administración denegados para ese rol.
- Diez activaciones secuenciales válidas del 20/10: media 1,977 s, mediana 2,053 s, mínimo 1,652 s y máximo 2,260 s. Incluye todo el recorrido hasta primera respuesta LMS 200; no tiempo aislado de Flow-Mod.
- Continuidad: antes 22/23 consultas en 45,032 s; después 24/24 en 45,015 s. Un ensayo por versión; no se descartan cortes entre sondeos.
- Contraseña incorrecta y cuenta deshabilitada rechazadas, contrastadas con SQL y acceso. Reactivación recuperó el acceso.
- Logout, revocación DTI y vencimiento natural de sesión contrastados con SQL/OVS/tráfico.
- Dos terminales con la misma cuenta: revocar h1 bloqueó h1 y conservó h2 con HTTP 200.
- Discrepancia controlada: puerto registrado 2→3 provocó revocación antes de vencer. Se restauró 2 sin reactivar la sesión. No fue un ataque real de suplantación.
- Cinco ensayos de logout: respuesta media 0,794 s; primera consulta sin respuesta completada media 1,796 s, incluido aproximadamente 1 s de timeout. No es latencia exacta de retiro OpenFlow ni revocación DTI.
- Concurrencia exploratoria: controles h1 2,168 s y h2 1,761 s. Pareja 01: 4,283/4,809 s; pareja 02 posterior a corrección de estado: 4,554/3,933 s. Cada cliente 30/30 consultas durante 60 s. Solapamiento estimado de pareja 02: 59,38 s. No representa capacidad máxima ni prueba causal de rendimiento entre versiones.
- Compatibilidad funcional básica: Chrome y Edge en Windows 11, con excepción TLS del laboratorio. No compatibilidad completa con todos los motores.

Bitácora con capturas: `../Planificacion_SEM09_SEM10_Exposicion_G2/Bitacora_pruebas_R1_Paola_G2.docx`. JSON y resúmenes en `../Mediciones_R1_G2/`. Los TXT del 21/10 son históricos y sus pendientes no sustituyen las pruebas del 22/10.

## Decisiones y mejoras futuras que no se deben presentar como implementadas

Mantener separación de sesión, autorización y reenvío. Estudiar permisos compartidos por rol, propiedad independiente de reglas compartidas y de sesión, reducción de renovaciones innecesarias y pruebas de carga. Primero medir versión actual, luego un piloto compartido para LMS y comparar. Conservar revocación individual y retorno correcto.

Compartir roles requiere rediseñar metadata/clasificación, generador, reconciliador, retorno y persistencia de reglas; no es solo cambiar MySQL. No se ha probado ahorro de memoria, superioridad frente a tabla única, TCAM física ni capacidad para campus.

Consultar también `../Mediciones_R1_G2/Diseno_multitable_tradeoffs_y_mejoras_R1_R2_20261022.md`, copiado a este paquete como `06_Detalle_multitable_y_mejoras.md` para conservar el contexto al subir la documentación.

R5 detección/mitigación y trabajo de Matthew se integran después de comparar versiones. No sobrescribir su variante con el generador o conteos de Paola. Una parte de recursos R5 se solicitó para el slice de Matthew, código 20222079; no consta aquí su despliegue completado.

## Estado de preservación al entregar estas guías

- Documentación y scripts locales preparados.
- Exportación viva de los ocho nodos, dump SQL, descarga y comprobación: pendientes de ejecutar.
- Push al repositorio indicado: pendiente; Paola pidió hacerlo personalmente.
- Limpieza de slice y despliegue ONOS: no ejecutados.
- Restauración integral: procedimiento preparado; aún no ensayado.
