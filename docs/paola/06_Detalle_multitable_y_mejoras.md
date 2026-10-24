# Multitable R1/R2: explicación, decisiones y mejoras propuestas

Fecha: 22 de octubre de 2026. Contexto: slice de Paola, Grupo 2, VNRT.

Este archivo conserva las explicaciones discutidas y sirve de referencia para continuar el trabajo. No registra la implementación de las mejoras propuestas ni autoriza sustituir la versión funcional. Consultarlo al retomar la optimización de R1/R2. No mezclar los conteos o el diseño de este slice con la variante de Matthew sin comparar ambos códigos.

## 1. Por qué elegimos multitable

La justificación respaldada por nuestra implementación es separar las funciones y reutilizar etapas: clasificación, habilitación de sesión, autorización por recurso y reenvío. R1 controla la sesión del terminal; R2 decide a qué recursos puede acceder.

El beneficio no es solo ordenar el código. Una sesión existente sirve para varios permisos; se puede cambiar una autorización sin rehacer la identidad ni el reenvío; todos los accesos protegidos atraviesan un control común de sesión; y las tablas permiten localizar dónde se bloquea un paquete.

Una sola tabla también puede aplicar estas políticas y revocar sesiones. No hemos demostrado que multitable sea más rápido, consuma menos memoria o soporte más usuarios. Tampoco es necesariamente más fácil de programar: requiere controlar saltos, metadata y el tratamiento de ida y retorno.

## 2. Funcionamiento de las tablas en sw2

| Tabla | Pregunta | Función actual |
|---|---|---|
| 0 | ¿Qué tráfico es? | Permite excepciones de portal, DHCP y ARP; encamina candidatos TCP protegidos hacia la tabla 10; descarta lo no autorizado por sus reglas. |
| 10 | ¿Este terminal tiene sesión habilitada? | Reglas individuales de ida y retorno validan campos del terminal, escriben metadata y continúan a la tabla 20. |
| 20 | ¿Puede acceder a este recurso? | Permisos concretos terminal–recurso comprueban identidad/contexto, IP y puerto del servicio; si coinciden, continúan a la tabla 30. |
| 30 | ¿Por dónde se envía? | Reenvía hacia el enlace de salida o hacia el terminal en el retorno. |

La metadata actual distingue clientes: h1 usa 0x1 y h2 usa 0x2. No representa el rol. Es contexto interno del procesamiento en sw2; no viaja automáticamente por el enlace hacia sw3. La aplicación consulta el rol en MySQL y lo transforma en permisos por terminal. En sw3 también existen reglas de permiso para ida y retorno hacia el servidor.

El paquete pasa por controles sucesivos; no se crean cuatro copias. El portal puede estar disponible antes del login sin que los recursos protegidos estén accesibles.

### Ejemplos sencillos

- Sin sesión: se puede abrir el portal; un intento al LMS no supera el control de sesión.
- Estudiante con permiso al LMS: supera clasificación, sesión, autorización y reenvío.
- El mismo estudiante intenta Notas: supera el control de sesión, pero no el de autorización.
- Docente con permisos configurados para LMS y Notas: puede acceder a ambos. El acceso administrativo requiere su permiso explícito. Este ejemplo describe una política, no una prueba adicional ejecutada.
- Administrativo: solo puede acceder a los recursos que su política permita; el nombre del rol no concede acceso general.
- Logout: se retiran la habilitación individual y los permisos asociados. Se conserva el acceso al portal para un nuevo login.
- Misma cuenta en h1 y h2: son sesiones distintas. Revocar h1 no debe eliminar la sesión de h2; lo comprobamos funcionalmente.

Analogía: tabla 0 es la recepción; tabla 10 revisa la credencial del terminal; tabla 20 revisa qué salón puede visitar; tabla 30 indica el camino. En una sola tabla, un guardia combina todas esas condiciones en las reglas de una sola lista.

## 3. Conteo y trade-off actual

Para el catálogo y la topología actuales de Paola, sumando reglas propias de los tres switches:

**Reglas = 52 base + 2 por sesión habilitada + 4 por permiso terminal–recurso.**

Las cuatro reglas por permiso cubren ida y retorno en sw2 y sw3; no corresponden a las cuatro tablas. Con una sesión y un permiso al LMS: 58 reglas propias. Con dos sesiones y un permiso cada una: 64. Se excluyen reglas internas adicionales que pudiera instalar Floodlight.

La fórmula describe esta topología y este generador; no debe extrapolarse literalmente a un campus. Al añadir terminales o cambiar la topología también puede cambiar el catálogo base.

Trade-off: obtenemos separación, reutilización parcial, control y diagnóstico, a cambio de complejidad y entradas adicionales en esta implementación. El crecimiento de permisos por combinación terminal–recurso es una limitación del diseño actual, no una consecuencia inevitable de multitable.

Añadir un rol en la base de datos no instala por sí solo reglas si nadie lo utiliza. Añadir un recurso requiere incorporarlo al catálogo y a la configuración de red; los permisos nuevos reutilizan las reglas de identidad y reenvío existentes, pero pueden exigir reglas base adicionales de tránsito.

Usamos Open vSwitch de software. No hemos medido ocupación de TCAM física. El número de reglas OpenFlow no equivale por sí solo al consumo real de memoria o al costo de reenvío; influyen la implementación, los campos, las cachés y la carga.

## 4. Mejora propuesta: compartir permisos por rol

Actualmente, para cien estudiantes autorizados al LMS se generan permisos por cada terminal. La propuesta es conservar identificación individual, pero clasificar el tráfico validado por rol y reutilizar políticas comunes como «Estudiante → LMS».

Esto podría reducir la repetición cuando muchas personas tienen los mismos permisos. Conceptualmente, parte del crecimiento pasaría de combinaciones terminal × recurso a identidades individuales + políticas rol × recurso. No significa que cien usuarios necesiten una sola regla total: siguen haciendo falta identificación, retorno, reenvío y controles adicionales.

Requiere rediseñar la metadata o contexto de clasificación, las reglas de autorización y el retorno, así como la verificación que hace el adaptador. La metadata es local al switch; no se debe asumir que sw3 recibe la clasificación de sw2. Hay que decidir dónde se exige la política y cómo se conserva la protección del recurso.

Agregar un servicio común podría requerir modificar una política compartida en lugar de repetirla para todos los terminales en cada punto. El ahorro real se contará después de implementar y validar el diseño.

## 5. Mejora propuesta: separar reglas compartidas y reglas de sesión

Pregunta central: ¿qué se elimina cuando una persona cierra sesión?

En el diseño propuesto, la regla general «Estudiante → LMS» permanece mientras sea válida la política. Cada terminal conserva una habilitación individual. Cuando Ana cierra sesión se retira su habilitación; Luis sigue utilizando la política compartida.

Actualmente ya separamos identidad y autorización por tablas, pero los permisos están ligados a la sesión. El adaptador elimina identidad y permisos al retirarla. Para compartir reglas hay que cambiar su propiedad y ciclo de vida: una sesión no puede ser dueña exclusiva de una regla que usan otras.

Esto afecta nombres de reglas, cookies si se usan para su gestión, enlaces en network_rules, estado esperado del reconciliador, limpieza y comprobaciones SQL/OVS. Hay que garantizar que ningún terminal sin sesión acceda a una política compartida, y que revocar un terminal no afecte a los demás.

Compartir por rol y separar propiedad/ciclo de vida son partes de un mismo rediseño; conviene diseñarlas juntas.

## 6. Mejora propuesta: revisar la renovación periódica

El adaptador actual utiliza reglas temporales de hasta 30 segundos e intenta renovarlas aproximadamente cada 10 segundos. Así, si no se renuevan, los permisos terminan venciendo. Con muchas sesiones y permisos crece el trabajo periódico, aun cuando no cambia la política ni hay mucho tráfico.

Posibles mejoras:

- Mantener políticas compartidas mientras no cambie su configuración.
- Concentrar el vencimiento corto en las habilitaciones individuales.
- Actualizar solo lo necesario y evaluar intervalos de renovación.
- Mantener el retiro inmediato solicitado por logout o revocación, independientemente del vencimiento de respaldo.

Menos renovaciones pueden reducir carga, pero ampliar el vencimiento puede prolongar el permiso residual si falla el retiro. No cambiar intervalos sin definir y probar el comportamiento ante caída del adaptador, desconexión del controlador, reinicio y pérdida de comunicación.

La corrección de continuidad ya aplicada evitó borrar y reinstalar las mismas reglas al renovarlas: ahora se actualizan conservando sus nombres y se eliminan solo las obsoletas. No eliminó la renovación periódica. Esta nueva optimización sería un cambio distinto.

## 7. Mejora propuesta: medir bajo carga

Separar tres cargas:

1. Muchos logins simultáneos: portal, MySQL, adaptador y controlador.
2. Muchas sesiones mantenidas: almacenamiento de reglas y renovaciones.
3. Mucho tráfico con permisos instalados: procesamiento y reenvío.

Varias conexiones desde h1 no representan varias identidades o sesiones independientes. Añadir identidades sintéticas requiere preparar puertos, MAC/IP, inventario y observación del terminal compatibles con el diseño; no basta repetir el login en h1.

Medir activación, retiro, errores, reglas por tabla y switch, CPU y memoria de componentes, tráfico entregado y pérdidas. El tiempo de activación medido incluye portal, consultas, aplicación de reglas y respuesta del LMS; no es una medición aislada de TCAM ni de instalación de flujos.

Para comparar una tabla y multitable: mismas políticas y restricciones, mismo entorno, misma carga, repeticiones y orden alternado. Distinguir conexiones nuevas de tráfico sostenido por la caché de OVS. Definir de antemano los criterios aceptables y reportar solo el límite observado bajo esas condiciones.

iperf3 puede medir tráfico en un servicio de prueba específicamente autorizado en ambas variantes; sus puertos no están permitidos automáticamente por nuestras políticas HTTPS actuales.

## 8. Qué está demostrado

- Funcionamiento del ciclo de sesión, rechazo de credenciales/cuenta deshabilitada, logout, revocación administrativa, vencimiento y revocación independiente en las pruebas documentadas.
- Prueba negativa de discrepancia controlada en el puerto registrado; no equivale a una campaña completa de suplantación.
- Dos clientes concurrentes, cada uno mantenido durante 60 segundos, con 30 consultas exitosas por cliente en la repetición posterior a la corrección de estado.
- Dos clientes es el alcance probado, no la capacidad máxima.
- No se ha demostrado ahorro de memoria, ventaja de rendimiento frente a tabla única, capacidad de campus ni consumo de TCAM física.

## 9. Magnitud del cambio en el VNRT

| Propuesta | Alcance estimado | Componentes afectados |
|---|---|---|
| Instrumentar y medir la versión actual | Bajo a medio | Scripts de medición, monitoreo y, para tráfico específico, servicio/política de prueba. No exige rediseñar las tablas. |
| Ajustar renovación conservando el modelo actual | Medio y sensible a fallos | Adaptador, temporizadores, retiro y pruebas de recuperación. Cambiar un número es fácil; validar su efecto no. |
| Compartir permisos por rol y separar reglas de sesión | Medio a alto | Generador de flujos, reconciliador, clasificación/metadata, retorno, propiedad de reglas, persistencia y pruebas. No es solo una modificación en MySQL. |
| Aumentar clientes de prueba | Variable | Identidades, interfaces/puertos, inventario, observación y capacidad disponible. No exige necesariamente una VM por usuario, pero el laboratorio actual tiene h1/h2 definidos explícitamente. |

Podemos conservar Floodlight, OVS, MySQL y la idea de cuatro tablas. No implica rehacer todo el laboratorio, pero el rediseño de políticas compartidas sí afecta el núcleo que decide, instala, verifica y retira reglas. El esquema SQL podría requerir ajustes según cómo representemos políticas compartidas; se decide al diseñar, no se presupone una migración obligatoria.

Ruta recomendada: conservar respaldo funcional y evidencias; medir primero el estado actual; comparar la variante de Matthew; diseñar un permiso compartido para LMS como piloto en una copia o ventana de prueba; validar usuarios del mismo y distinto rol, ida/retorno, logout selectivo, cambio de rol, deshabilitación, vencimiento, reinicios y fallos; luego medir reglas y carga contra la referencia. Evitar cambiar simultáneamente política, renovación y medición, porque impediría atribuir los efectos.

La mejora puede ser importante con muchos usuarios de políticas similares, pero su magnitud y la capacidad alcanzable deben medirse. No prometer cifras de ahorro ni usuarios soportados antes de la evaluación.

## 10. Respuesta breve para la exposición

«Elegimos multitable para reutilizar el control de sesión y el reenvío, manteniendo la autorización por recurso separada. Nuestro prototipo todavía genera permisos por terminal, por lo que proponemos compartir políticas por rol y optimizar su mantenimiento. Validamos dos clientes concurrentes; la capacidad máxima y el beneficio de esas optimizaciones quedan pendientes de pruebas de carga».

## Fuentes técnicas de contexto

- Arquitectura de FAUCET: https://docs.faucet.nz/en/latest/architecture.html — ejemplo de uso de un pipeline multitable para ACL, conmutación y enrutamiento; no valida el rendimiento de nuestro prototipo.
- Implementación de OVS: https://docs.openvswitch.org/en/latest/faq/design/ — diferencia entre reglas OpenFlow y flujos internos del datapath.
- Tutorial OVS/FAUCET: https://docs.openvswitch.org/en/stable/tutorials/faucet/ — pipeline y caché de procesamiento.
- iperf3: https://software.es.net/iperf/invoking.html — medición de tráfico.

Referencias locales: vnrt_avz7_adapter_corregido_20261022.py, bitácora R1 y resúmenes de activación, logout y concurrencia en esta carpeta. Las propuestas de este archivo no sustituyen esos resultados originales.
