# Migración R1 R2 a multitabla del 21 de octubre de 2026

## Alcance

Se conserva la matriz de permisos y su activación automática al iniciar sesión. sw2 utiliza tablas 0, 10, 20 y 30; sw1 conserva tránsito común; sw3 conserva tabla 0. No se implementa R5, no se introduce VLAN y no se modifica el gateway ni la administración SSH.

Antes de migrar, guardar un respaldo privado de código, configuración y base de datos. No publicar ese respaldo.

## Matriz conservada

| Rol | LMS TCP 443 | Notas TCP 443 | Administrativo TCP 8443 |
|---|---|---|---|
| Estudiante | Sí | No | No |
| Docente | Sí | Sí | No |
| Administrativo | No | No | Sí |
| Visitante | No | No | No |

DTI continúa siendo gestión separada. LMS es el servicio general R1; Notas y Administrativo son los recursos privilegiados R2.

## Procesamiento

| Equipo y tabla | Tratamiento |
|---|---|
| sw2 tabla 0 | Excepciones DHCP, ARP, portal y descubrimiento. El resto continúa a tabla 10. |
| sw2 tabla 10 | Dos clasificadores IPv4 por sesión: puerto/MAC/IP de origen en ida y uplink/MAC/IP de destino en retorno. Escriben metadata y continúan a tabla 20. Sin clasificador, DROP. |
| sw2 tabla 20 | Dos políticas compartidas para LMS, condicionadas por metadata de elegibilidad y dirección. Dos entradas por permiso privilegiado con coincidencias exactas. Solo lo autorizado continúa a tabla 30. |
| sw2 tabla 30 | Dos salidas por sesión, seleccionadas por su metadata exacta: uplink y puerto de terminal. Lo no reconocido se descarta. |
| sw1 tabla 0 | Tránsito acotado existente. No se añaden reglas por sesión. |
| sw3 tabla 0 | Dos entradas comunes de LMS desde/hacia el uplink confiable. Para cada permiso privilegiado R2, ida y retorno individuales. DROP por defecto. |

La metadata no viaja por Ethernet entre switches. El bit 62 expresa elegibilidad LMS, bits 48 a 55 identifican el rol de la aplicación, bits 1 a 47 contienen una etiqueta derivada de la sesión y el bit 0 indica ida/retorno. Se comprueba la ausencia de colisión entre contextos simultáneos. La etiqueta no es una credencial ni el token de sesión.

Se evita el bit 63 porque el parser de esta versión de Floodlight rechazó valores que excedían el rango positivo de un entero largo de Java. El ensayo se hizo en tablas inalcanzables y las reglas temporales se retiraron.

Los permisos y clasificadores mantienen prioridad 500 y lease de hasta 30 segundos. Las reglas compartidas del LMS usan prioridad 400 en tabla 20 y 350 en sw3. Las prioridades se comparan dentro de cada tabla, no entre switches. Las salidas conservan la autorización previa: no hay NORMAL ni un camino permisivo alternativo.

## Renovación y revisión

Un solo trabajador recibe solicitudes de sincronización sin permisos almacenados en la cola. Lee una instantánea fresca de sesiones y políticas. Una revisión monotónica en MySQL cambia cuando se modifican datos relevantes de cuenta, sesión, recurso o permiso. Antes de cada instalación y después de verificar el dataplane se comprueban revisión y contenido de autorización; se rechaza el trabajo obsoleto.

Las renovaciones continúan aproximadamente cada 10 segundos mediante retiro y ADD, porque no se ha validado que el MODIFY de este Floodlight renueve correctamente el timeout. No se afirma que esta versión reduzca el número de llamadas REST. El lease se limita también al tiempo restante de sesión, reservando dos segundos al calcularlo; esto no constituye una garantía temporal bajo cualquier demora de red o carga. Si una operación queda bloqueada el permiso puede vencer y el tráfico permanece restringido.

Una instalación parcial o revisión obsoleta retira las entradas individuales y vuelve a evaluar. Las políticas base compartidas permanecen, pero no autorizan tráfico sin clasificación válida. Este comportamiento prioriza seguridad y puede interrumpir temporalmente otras sesiones durante una recuperación. La revisión es global, no una cola distribuida ni una versión independiente por permiso. Es una elección conservadora para esta maqueta.

Un fallo transitorio de aplicación de reglas no elimina automáticamente la cookie de una sesión todavía válida. El portal solicita reconciliación y devuelve error de disponibilidad si no puede confirmar la aplicación. Revocación y vencimiento sí invalidan el acceso.

## Conteos para la topología actual

Reglas propias base: sw1 19, sw2 20 y sw3 9; total 48. Las entradas internas de Floodlight se contabilizan aparte.

Cada sesión añade cuatro entradas de clasificación y salida en sw2, aunque el visitante no tenga servicios permitidos. Cada permiso privilegiado añade dos entradas en tabla 20 de sw2 y dos en tabla 0 de sw3. LMS utiliza políticas compartidas y no suma cuatro entradas por sesión como en la versión anterior.

| Estado | sw1 propias | sw2 propias | sw3 propias | Total propias |
|---|---:|---:|---:|---:|
| Sin sesiones | 19 | 20 | 9 | 48 |
| Estudiante con LMS | 19 | 24 | 9 | 52 |
| Docente con LMS y Notas | 19 | 26 | 11 | 56 |
| Administrativo | 19 | 26 | 11 | 56 |
| Visitante autenticado | 19 | 24 | 9 | 52 |
| Estudiante y docente | 19 | 30 | 11 | 60 |

Para los dos terminales inventariados, S son sesiones activas y G son permisos privilegiados activos: total propio = 48 + 4S + 4G. En sw2 es 20 + 4S + 2G; en sw3 es 9 + 2G. No extrapolar este catálogo a más terminales sin adaptar inventario y reglas iniciales. El término de reglas iniciales de cada terminal incluye ARP, DHCP y portal; no se ha implementado la hipótesis de solo 2L entradas iniciales del parcial.

En régimen nominal sin errores, renovar grupos completos demanda aproximadamente 0,8(S + G) modificaciones REST por segundo, más consultas y verificaciones. Los cambios de política pueden reinstalar todo el grupo del terminal. No es capacidad medida. Multitabla por sí misma no reduce necesariamente entradas ni CPU; debe compararse con la versión anterior con los mismos roles y permisos.

## Archivos y arranque

Los módulos vigentes se añaden, sin sobrescribir los originales:

- `/opt/sdn-portal-paso4/vnrt_mt_red.py`
- `/opt/sdn-portal-paso4/vnrt_mt_adapter.py`
- `/opt/sdn-portal-paso4/vnrt_mt_portal.py`

Los drop-ins `80-multitabla.conf` de Floodlight, adaptador y portal seleccionan los nuevos puntos de entrada. Al reiniciar Floodlight se reconstruye la base multitabla. Las sesiones todavía vigentes se reevalúan; no se concede acceso basándose solo en una cookie.

Comprobar:

```bash
systemctl is-active sdn-floodlight sdn-r1 sdn-portal sdn-admin mysql sdn-dhcp
sudo ovs-ofctl -O OpenFlow13 dump-flows sw2
sudo ovs-ofctl -O OpenFlow13 dump-flows sw3
```

Los comandos OVS se ejecutan en cada switch correspondiente. En sw2 deben aparecer tablas 0, 10, 20 y 30; metadata en los clasificadores aparece cuando existe una sesión activa.

## Recuperación

El instalador de migración del controller permite volver al catálogo anterior sin restaurar sesiones antiguas:

```bash
sudo python3 /home/ubuntu/instalar_controller.py rollback
```

Detiene portal y adaptador, retira únicamente entradas `g2-mt-`, elimina únicamente sus tres drop-ins `80-multitabla.conf`, reconstruye la base anterior y arranca los servicios previos. Los módulos originales no se sobrescribieron. La tabla de revisión y sus triggers pueden permanecer: el código anterior no depende de ellos. El respaldo SQL completo no debe restaurarse salvo necesidad revisada, porque también revertiría auditoría y datos posteriores.

## Evidencia y límites

Los resúmenes históricos publicados están en `../pruebas/r2/resultados-historicos/`. Consultar archivos de resultados y sus comprobaciones; una prueba fallida se conserva y no se transforma en aprobada sin repetir el ensayo. No se han medido capacidad máxima, P95 de una campaña de carga ni TCAM física. No se ha validado todavía esta actualización en el VNRT de compañeros.

Resultados al cierre: piloto 5/5 comprobaciones; campaña funcional 24/24 comprobaciones (incluye 24 consultas de la matriz, cuatro roles por tres recursos por dos terminales; 16 consultas R2 y 8 de LMS); consistencia 8/8; ubicación y arranque 8/8. Son comprobaciones funcionales de casos distintos, no repeticiones estadísticas independientes ni porcentajes de eficacia general. Las fallas iniciales de recuperación y arranque se conservaron en JSON separados y se corrigieron antes de repetir.

Se guardaron volcados nativos de sw1/sw2/sw3 con estudiante y docente activos y al terminar sin sesiones. Estado final: seis servicios activos, cero entradas individuales verificadas en el registro de reglas, 48 entradas propias base más tres entradas internas de Floodlight en los volcados. El disco del controller quedó al 86 %, aproximadamente 830 MiB disponibles; no se borraron respaldos ni registros históricos para completar la migración. Conviene solicitar la ampliación de almacenamiento ya planteada.

El control de vínculo se ensayó alterando el puerto registrado de la sesión; no equivale a una campaña de suplantación real de paquetes ni a validación directa de concesiones Kea. Tampoco se simuló una caída completa de la VM ni se garantiza disponibilidad durante cambios de política.

El paquete `VNRT_MULTITABLA_ACTUALIZACION_20261021.zip` contiene una actualización para quien ya instaló el portable anterior, no un instalador limpio autónomo. El informe compartido de Drive y el repositorio GitHub no se modificaron durante esta migración.
