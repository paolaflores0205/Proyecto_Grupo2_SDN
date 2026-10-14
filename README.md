# Proyecto Grupo 2 SDN — código del parcial

Implementación VNRT de R1/R2: portal HTTPS, autenticación y sesiones, autorización por rol, aplicación Python, administración DTI, MySQL, Kea DHCP, Floodlight y OVS/OpenFlow 1.3.

- `despliegue-portable/`: paquete configurable y guía de instalación. Leer README.md, GUIA_CODEX.md y VALIDACION.md antes de ejecutar. Los nombres históricos son dependencias del código vigente; no ejecutar scripts por separado.
- `vnrt-actual/`: solo aparece si fue posible obtener una captura por SSH en modo lectura. Consultar ESTADO_EXPORTACION.json; si no existe esta carpeta, se publica únicamente la versión portable archivada del 10/10, no una captura nueva del VNRT.
- `ESTADO_EXPORTACION.json`: alcance y disponibilidad de la captura actual.

R5/Suricata siguen pendientes. No se incluyen contraseñas, claves privadas, certificados privados, cookies, datos MySQL, respaldos ni evidencias de usuarios. El JAR de Floodlight NO se sube al repositorio: antes de generar un despliegue, obtenerlo del paquete portable original o de la instalación autorizada en /opt/sdn-floodlight/floodlight.jar y colocarlo en despliegue-portable/vendor/floodlight.jar. Se conservan sus avisos de licencia. La instalación portable requiere adaptar IP, MAC, DPID, interfaces y puertos al destino.

La instantánea no incluye configuraciones privadas de /etc ni datos de /var/lib. El paquete portable genera secretos y certificados nuevos. No se modificó el VNRT para esta exportación.
