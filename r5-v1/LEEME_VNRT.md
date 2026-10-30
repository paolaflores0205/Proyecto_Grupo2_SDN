# R5 de Adrian en carpeta independiente

Esta carpeta no pertenece a R1/R2. No instala servicios ni modifica /opt, /etc o la base MySQL del proyecto. Solo requiere Python3 y su biblioteca estándar. No ejecutar bootstrap ni reiniciar Floodlight para usarla.

La política policy.vnrt-interno.json propone bloquear durante 60 segundos únicamente h1 (192.168.10.1) hacia LMS (192.168.10.101:443), entrando por sw1:2. No se ha aplicado por subir o comprobar estos archivos. Es un ensayo interno con evento sintético; no representa detección de Suricata ni prueba perimetral completa. h2 puede servir de control si tiene una sesión R1 válida y acceso previo comprobado al LMS.

## Estado de esta entrega

Subida de archivos y comprobaciones de lectura. No hay demonio, tarea programada ni proceso automático que instale reglas. make_event.py escribe una alerta local; vnrt.py check solo consulta. apply y retire son acciones separadas y explícitas para la ventana de prueba acordada.

El JSON de salud del portal ejecuta sincronización de políticas; no se usa como lectura inocua. Los snapshots consultan únicamente la API de observación de Floodlight y el estado de servicios.

## Antes de una prueba real

Comprobar de nuevo topología, sesiones válidas y respuestas HTTPS desde h1 y h2 usando los certificados de confianza existentes. Preparar registro del ensayo y capturas de regla/tráfico. No iniciar el bloqueo hasta tener un control positivo y el comando de retiro a mano. La fecha del evento debe ser reciente; no cambiar su ID para reintentar una instalación incierta.

La regla tiene nombre g2-r5-adrian- seguido de un identificador y no pertenece a los prefijos g2-mt-session/grant. Aunque no cambia las autorizaciones R1/R2, impide deliberadamente el flujo del ensayo mientras está vigente. Su convivencia con la renovación se debe comprobar con tráfico real.

## Retirada de R5

Si todavía no se ejecutó apply, no hay ninguna regla R5 que retirar. Se puede conservar esta carpeta inactiva o archivarla; R1/R2 no importa ninguno de sus archivos.

Si se ejecutó apply, usar vnrt.py retire con la misma política, bitácora SQLite y event-id del ensayo. El comando solo puede retirar la entrada registrada como propia y comprueba el pusher y el dataplane. Conservar los resultados originales. No borrar la bitácora ni la carpeta hasta confirmar ausencia de la regla y recuperación del servicio.

Si hay fallo de control, no prometer retiro instantáneo: la regla tiene hard_timeout de 60 segundos, cuyo vencimiento se debe comprobar en OVS. Si Floodlight o su política de reconexión cambia, revisar su estado antes de continuar; este componente no modifica esa configuración.

## Límites

RULE_VERIFIED_TRAFFIC_PENDING significa regla observada, no bloqueo efectivo probado. RULE_RETIRED_RECOVERY_PENDING tampoco demuestra por sí solo recuperación. Esas comprobaciones se realizan desde los clientes y se relacionan con OVS. No mostrar los tiempos de la demo local como latencias del VNRT.

El adaptador ha sido adaptado a la representación OFFlowMod e instrucciones none:drop observadas por lectura en este build. La primera instalación y su retirada todavía deben probarse en la ventana acordada.
