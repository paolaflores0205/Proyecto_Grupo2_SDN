# Componente local de mitigación R5

Componente para que Adrian revise la lógica antes de desplegar en VNRT. La demo y el planificador no envían reglas. El adaptador separado floodlight.py implementa la comunicación con la interfaz Static Flow Pusher identificada en el slice; aún no ha sido ejecutado contra ese controlador. Incluye un doble de prueba del switch y una API ficticia para ejercitar errores, duplicados y retiro.

La demo y los tests funcionan sin red y sin Suricata. No modifican R1/R2, MySQL del laboratorio, servicios, interfaces ni reglas reales. Solo crean evidencia local. vnrt.py dispone de acciones reales explícitas que no se han ejecutado en el slice y requieren revisión previa del ensayo.

## Archivos

| Archivo | Función |
|---|---|
| r5.py | Validador, política, generador de regla, registro SQLite y backend simulado |
| policy.example.json | Alcance ilustrativo del ensayo; no es configuración real de VNRT |
| demo.py | Ejecuta un ciclo local con evento sintético, duplicado, rechazo, retiro y expiración |
| plan.py | Lee un evento normalizado y muestra la regla propuesta sin enviarla |
| test_r5.py | Casos automatizados de comportamiento y manejo de errores |
| floodlight.py | Cliente HTTP loopback, consulta de conflictos, instalación y retiro de reglas propias |
| vnrt.py | CLI real: check solo lectura; apply/retire requieren habilitación explícita |
| test_floodlight.py | API ficticia y pruebas del transporte, sin abrir conexiones de red |

Requiere Python 3.10 o posterior. Solo usa la biblioteca estándar; no instala dependencias. En este chat se verificó con Python 3.12.3 del runtime disponible.

## Ejecución local

Desde la raíz del proyecto, con Python disponible:

```text
python -m unittest discover -s r5_mitigacion -p "test_*.py" -v
python r5_mitigacion/demo.py --output output/r5_demo_nuevo
```

La carpeta de salida debe ser nueva: la demo se detiene si ya existe para conservar las evidencias previas. Genera evento, política, JSON de regla propuesto, resultados simulados y una base SQLite independiente. Nunca usar la base MySQL de R1/R2 para esta demo.

La salida muestra SIMULATED_RULE_VERIFIED para una regla correctamente observada en el simulador. Esto no significa que exista en OVS o que haya bloqueado paquetes. traffic_block_verified y service_recovery_verified permanecen false.

El reloj adelantado para el caso de expiración pertenece al objeto simulado. No modifica el reloj de Windows ni de ninguna VM.

## Contrato propuesto de entrada

| Campo | Significado |
|---|---|
| schema_version | 1 |
| event_id | ID estable que conserva el colector al retransmitir una alerta |
| trial_id | Ensayo autorizado |
| timestamp | Instante original de alerta, ISO 8601 con zona horaria |
| sensor_id | Identificación esperada del emisor; el campo no autentica al emisor |
| source_mode | synthetic, replayed o live; se conserva la naturaleza de la entrada |
| event_type | alert |
| direction | request en esta versión; no se bloquea automáticamente el origen de alertas de respuesta |
| src_ip, dest_ip | Extremos IPv4 individuales, observados en el punto de control |
| proto | TCP o UDP en esta versión |
| src_port, dest_port | Puertos reales del evento |
| signature_id, signature | Identificador y descripción de la firma |

El evento no puede elegir DPID, tabla, prioridad, acción, puerto OVS ni duración. Estos valores proceden de una política local revisada. El ejemplo usa direcciones de documentación 192.0.2.x y un DPID/puerto ilustrativos, no las direcciones del slice.

Para EVE, normalize_eve conserva los campos de la alerta y recibe el contexto del colector. No transforma eventos sin puertos en TCP/UDP ni inventa valores. ICMP y alertas de otros sentidos requieren ampliar la política y las comprobaciones; esta versión los rechaza.

Se debe conservar el EVE original por separado y vincularlo con el ID del evento normalizado y su hash. Por ejemplo, el colector puede derivar un ID estable con SHA-256 de sensor_id y la representación canónica del EVE original. No generar un ID nuevo en cada reintento. El contrato debe contrastarse con Lingan antes de integrar.

La antigüedad de una alerta reproducida se evalúa usando su timestamp original: no reescribirlo para hacerla pasar como alerta nueva. Un ensayo con un EVE antiguo requiere una política de reproducción específica y revisada. La simulación actual genera un evento nuevo y lo marca synthetic.

## Decisión y registro

Solo se acepta el origen, destino, servicio, firma, sensor, sentido y ensayo enumerados en la política. El bloqueo es unidireccional y afecta al servicio de destino para ese origen; no restringe automáticamente todas las comunicaciones de la IP. No fija el puerto efímero de origen en la regla, para cubrir las conexiones del servicio durante la vigencia.

La regla propuesta utiliza tabla0, IPv4 /32, puerto de ingreso, protocolo, puerto de destino y acción vacía sin goto. La prioridad y el recorrido del pipeline deben comprobarse en el entorno antes de instalar: generar el JSON no demuestra precedencia efectiva. NAT y otras transformaciones requieren mapear las direcciones observadas.

Los nombres empiezan por g2-r5-adrian-, separados de los prefijos R1/R2 observados. El código solo retira reglas registradas como propias y comprueba que no hayan cambiado. Esa separación reduce el alcance de los cambios, pero todavía no demuestra ausencia de interferencia en VNRT: un bloqueo necesariamente afectará al flujo elegido aunque esté permitido por R1/R2.

SQLite guarda la entrada aceptada, hash, política, regla y estados, además de un historial. Un duplicado registrado no reinstala ni amplía el timeout, incluso tras reiniciar el proceso o retirar la medida. Un ID con contenido distinto se rechaza. Un fallo de instalación se considera incierto porque la regla podría haberse aplicado antes de perder la respuesta; requiere consulta/retirada, no reintento ciego. La versión no recupera automáticamente solicitudes pendientes tras una interrupción.

Una nueva alerta con ID diferente representa una nueva evaluación; esta versión no agrega incidentes por flujo o ventana. Lingan y Adrian deben acordar qué alertas son retransmisiones y cuáles son nuevos eventos antes de habilitar recepción automática.

## Adaptador de Floodlight y pasos pendientes para VNRT

El cliente HTTP real ya está preparado. No hay servidor receptor automático: el punto de entrada es un archivo JSON o la llamada process(event). La CLI solo admite fuente synthetic o replayed. No se habilita source_mode=live antes de implementar y comprobar un transporte autenticado.

El cliente usa HTTPConnection a loopback, sin proxy ni redirecciones, con timeout y límite de respuesta. No se expone la API 8080 al exterior. Las acciones reales se ejecutarían dentro del controller, no desde Windows usando la IP del gateway.

check solo usa GET para comprobar conexión del switch, ausencia del nombre propuesto y conflictos de prioridad en tabla0. No demuestra disponibilidad del servicio ni confirma el puerto físico: estas precondiciones deben comprobarse por separado. apply exige --confirm-controlled-test y una SQLite propia, valida el evento y registra antes de enviar. Nunca ejecuta bootstrap, vacía tablas o reinicia servicios. retire exige un evento de la bitácora existente; revisa también que la definición del pusher y la entrada del dataplane no hayan cambiado. La CLI rechaza destinos de gestión/control conocidos como SSH22, REST8080, OpenFlow6653 y MySQL3306.

Una regla observada devuelve RULE_VERIFIED_TRAFFIC_PENDING. Su retiro comprobado devuelve RULE_RETIRED_RECOVERY_PENDING. Estas respuestas no afirman bloqueo ni recuperación del servicio; las comprobaciones de tráfico continúan pendientes y ambos booleanos permanecen false.

El formato de estadísticas y las entradas listadas por el pusher se interpretan de forma estricta. Si el build devuelve una representación diferente, el código se detiene o no verifica el resultado. Habrá que inspeccionar esa respuesta; no se debe desactivar la comprobación para que el ensayo continúe.

Tras perder una respuesta, no borrar la bitácora ni reinyectar con otro ID para forzar una instalación. Consultar el estado y retirar la medida propia cuando corresponda. Un duplicado no reintenta automáticamente una operación incierta. El hard_timeout es un respaldo finito; su efecto real debe comprobarse en OVS.

Antes de habilitarlo en VNRT hay que:

1. Contrastar el evento y entrega con Lingan. Si se usa un receptor de red, autenticarlo y proteger el transporte; sensor_id por sí solo no basta. El diseño del informe propone HTTPS con mTLS, todavía no implementado aquí.
2. Revisar el inventario vigente y la política del ensayo; definir un recorrido disponible y autorizado. Un recorrido interno no demuestra protección del perímetro exterior.
3. Probar primero check y contrastar las respuestas con el build real, sin instalar. Después, en la ventana acordada, comprobar instalación, consulta, retiro y expiración de una regla propia. No importar ni ejecutar acciones bootstrap de R1/R2. La recuperación tras reconexión del controlador sigue pendiente: su configuración actual puede limpiar tablas y reejecutar bootstrap.
4. Probar acceso inicial, bloqueo efectivo, contadores/captura, control legítimo durante el bloqueo, coexistencia con renovaciones R1/R2 y recuperación. Conservar también los fallos.

Sin Suricata se puede comprobar en VNRT la mitigación iniciada con un evento sintético o reproducido y presentarla como integración parcial. La detección en vivo y la cadena IDS completa requieren Suricata, captura y transporte reales.

## Interpretación de las pruebas locales

Las pruebas cubren decisiones y estados del software. Un permiso R1/R2 ficticio que se conserva en el backend es una comprobación de alcance del código de retiro, no una prueba de coexistencia con el adaptador real. local_processing_ms es tiempo de procesamiento local simulado; no es tiempo de detección, rendimiento de Floodlight ni latencia de mitigación en red.

Se ejecutaron 35 tests: 18 del núcleo y 17 del adaptador; incluye el formato none:drop observado en Floodlight. El transporte HTTP se comprobó mediante un objeto de conexión ficticio; ninguna prueba abre sockets o contacta el VNRT. La simulación inicial del usuario permanece guardada en output/r5_demo_manual_01 y no se sobrescribe.
