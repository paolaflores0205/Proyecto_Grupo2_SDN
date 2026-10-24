# Proyecto Grupo 2 SDN

## Avance VNRT de Paola al 24 de octubre

- `vnrt-paola-20261024/`: código de la instalación multitabla respaldada en Paola. Se conservan rutas por nodo para reconocer qué copia ejecutaba cada servicio. No es un instalador ni una actualización automática para otro slice.
- `docs/paola/LEER_PRIMERO_EN_GIT.md`: avances, decisiones, mejoras futuras, respaldo, pausa para Lab5 y recuperación. Los identificadores de red son ejemplos ficticios; el inventario y los secretos reales permanecen fuera de Git.
- `REVISION_PAOLA_20261024.json`: procedencia y hashes de los archivos preparados.
- `despliegue-portable/`: paquete histórico de tabla única del 10/10. Se conserva sin cambios y no contiene las correcciones posteriores. No usarlo como instalador actualizado de la versión multitabla.

Las pruebas de Paola incluyen activación, continuidad, logout, revocación, vencimiento, cuenta deshabilitada, discrepancia controlada y dos clientes concurrentes. No demuestran capacidad máxima, rendimiento de TCAM ni superioridad frente a tabla única. R5 y las mejoras de políticas compartidas no se declaran completados.

El proyecto continuará en Matthew. Antes de aplicar estos archivos, comparar su versión R2 y adaptar inventario, dependencias y ciclo de vida de reglas. No reemplazar todo el código de Matthew con esta copia. Un pull solo descarga archivos.

La copia real del código recuperado se conserva en el workspace privado. Aquí se sustituyen IP/MAC/DPID conocidos por ejemplos, por lo que algunos archivos publicados no coinciden byte a byte con el respaldo. No se incluyen dump SQL, config.json, claves, tar.gz ni JAR de Floodlight. La restauración integral aún no se ha ensayado.

## Registro histórico anterior

El bloque siguiente corresponde al paquete original y su exportación anterior. `ESTADO_EXPORTACION.json` conserva ese registro de 2026-10-14; no describe el nuevo respaldo de ocho nodos.

# Proyecto Grupo 2 SDN — código del parcial

Implementación VNRT de R1/R2: portal HTTPS, autenticación y sesiones, autorización por rol, aplicación Python, administración DTI, MySQL, Kea DHCP, Floodlight y OVS/OpenFlow 1.3.

- `despliegue-portable/`: paquete configurable y guía de instalación. Leer README.md, GUIA_CODEX.md y VALIDACION.md antes de ejecutar. Los nombres históricos son dependencias del código vigente; no ejecutar scripts por separado.
- `vnrt-actual/`: solo aparece si fue posible obtener una captura por SSH en modo lectura. Consultar ESTADO_EXPORTACION.json; si no existe esta carpeta, se publica únicamente la versión portable archivada del 10/10, no una captura nueva del VNRT.
- `ESTADO_EXPORTACION.json`: alcance y disponibilidad de la captura actual.

R5/Suricata siguen pendientes. No se incluyen contraseñas, claves privadas, certificados privados, cookies, datos MySQL, respaldos ni evidencias de usuarios. El JAR de Floodlight NO se sube al repositorio: antes de generar un despliegue, obtenerlo del paquete portable original o de la instalación autorizada en /opt/sdn-floodlight/floodlight.jar y colocarlo en despliegue-portable/vendor/floodlight.jar. Se conservan sus avisos de licencia. La instalación portable requiere adaptar IP, MAC, DPID, interfaces y puertos al destino.

La instantánea no incluye configuraciones privadas de /etc ni datos de /var/lib. El paquete portable genera secretos y certificados nuevos. No se modificó el VNRT para esta exportación.

## Datos ficticios para publicación
Las IP de ejemplo utilizan redes de documentación 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24; MAC y DPID se sustituyeron por identificadores ficticios. No representan el VNRT actual. Deben reemplazarse con el inventario privado de cada destino. No usar estas direcciones para un despliegue real sin adaptación. Por esta sanitización, el contenido no es una copia byte a byte de los archivos originales. SHA256SUMS del paquete original no se incluye porque ya no correspondería a estos archivos.
