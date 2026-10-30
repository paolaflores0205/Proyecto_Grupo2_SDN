# Diseño de autorización R2 y dimensionamiento

R1 valida identidad y sesión. R2 combina sesión vigente, cuenta activa, rol, ubicación observada IP/MAC/DPID/puerto, permiso explícito y recurso desplegado con IP, TCP y puerto consistentes. MAC y metadata no son credenciales. DTI usa gestión separada; no equivale al rol administrativo del portal.

| Rol | LMS TCP/443 (general R1) | Notas TCP/443 (R2) | Administración TCP/8443 (R2) |
|---|---|---|---|
| Estudiante | Permitir | Denegar | Denegar |
| Docente | Permitir | Permitir | Denegar |
| Administrativo | Denegar | Denegar | Permitir |
| Visitante | Denegar | Denegar | Denegar |

Las IP se leen del inventario de destino: portal = controller, LMS = h3, Notas y Administración = h4. No se usan direcciones del laboratorio como configuración del proyecto.

Flujo: HTTPS al portal → validar sesión y política en MySQL → reconciliador → REST HTTP/JSON de Floodlight en loopback TCP/8080 → OpenFlow 1.3 TCP/6653 → reglas de ida y retorno en switches. La conexión de usuario al recurso sigue el plano de datos; el controlador no transporta la página.

| Lugar | Tratamiento |
|---|---|
| sw2 tabla 0 | DHCP UDP/67–68, ARP EtherType 0x0806, portal HTTPS/443 y descubrimiento; restante pasa a tabla 10. |
| sw2 tabla 10 | Dos clasificadores por sesión: ida con puerto/MAC/IP de origen; retorno con uplink/MAC/IP de destino. Escriben metadata y pasan a tabla 20. Sin coincidencia: DROP. |
| sw2 tabla 20 | Dos reglas compartidas de LMS, con máscara de elegibilidad y dirección. Dos reglas exactas adicionales por permiso R2, incluyendo metadata y recurso. Si autoriza pasa a tabla 30; de lo contrario DROP. |
| sw2 tabla 30 | Dos salidas por sesión según metadata exacta: uplink o terminal. No concede permisos por sí sola. |
| sw1 tabla 0 | Tránsito común acotado; no crece por sesión. |
| sw3 tabla 0 | LMS compartido hacia uplink confiable; dos reglas por permiso R2. DROP para tráfico no permitido. |

Metadata solo existe durante el procesamiento local de sw2: bit 62 = elegibilidad LMS, bits 48–55 = rol, bits 1–47 = etiqueta derivada de sesión y bit 0 = dirección. Diferentes sesiones conservan contextos diferentes, aunque las de LMS compartan el bit de elegibilidad. No se transmite metadata por los enlaces Ethernet.

Las entradas individuales tienen prioridad 500 y hard_timeout de hasta 30 s, limitado por el vencimiento de sesión. La renovación aproximada cada 10 s usa DELETE/ADD. Los permisos LMS compartidos tienen prioridades 400 en sw2/tabla20 y 350 en sw3/tabla0. Consultar el catálogo generado con `vnrt_mt_red.py show` para todos los match y acciones del inventario propio.

## Conteo

S = sesiones activas; G = permisos privilegiados activos asociados a sesiones. No son necesariamente usuarios únicos. Para esta topología de maqueta:

| Estado | sw1 | sw2 | sw3 | Total propio |
|---|---:|---:|---:|---:|
| Base sin sesiones | 19 | 20 | 9 | 48 |
| Un estudiante | 19 | 24 | 9 | 52 |
| Un docente | 19 | 26 | 11 | 56 |
| Un administrativo | 19 | 26 | 11 | 56 |
| Un visitante autenticado | 19 | 24 | 9 | 52 |
| Estudiante y docente | 19 | 30 | 11 | 60 |

Fórmulas: sw2 = 20 + 4S + 2G; sw3 = 9 + 2G; total = 48 + 4S + 4G. sw2 base por tabla: T0=15, T10=1, T20=3, T30=1. Por sesión se añaden 2 en T10 y 2 en T30; por permiso R2, 2 en T20. Las entradas internas de Floodlight se suman aparte: en la evidencia original había una por switch.

El visitante puede tener clasificación y salida de sesión, pero no una regla de autorización en T20; no llega a usar la salida de T30 para esos servicios. Las fórmulas no dimensionan automáticamente un campus: el catálogo incluye excepciones para h1/h2 y se debe extender por inventario de equipos/puertos.

## Consistencia y límites

Un trabajador obtiene bloqueo MySQL, lee revisión global e instantánea fresca y comprueba cambios antes de instalar y después de verificar el dataplane. Un permiso retirado no debe renovarse desde una decisión obsoleta. Ante error parcial, retira conservadoramente todas las reglas individuales propias, incluso las de otras sesiones; mantiene la base compartida y vuelve a evaluar. No es una actualización atómica de switches.

DELETE/ADD puede introducir interrupciones. El número nominal de operaciones de renovación de entradas individuales es aproximadamente (8S+8G)/10 = 0.8(S+G) por segundo, sin contar consultas, reintentos ni cambios de política. No es una capacidad medida. OVS permite contar flujos y medir CPU/RAM; no representa ocupación física de TCAM. No se ha demostrado capacidad para miles de usuarios.
