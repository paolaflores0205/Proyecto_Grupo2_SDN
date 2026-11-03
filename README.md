# Arquitectura SDN Grupo 2

Versión de conservación del 2 de noviembre de 2026, anterior al reemplazo de la infraestructura VNRT. Reúne la base de despliegue, R1/R2 multitabla, el código recuperado del respaldo original y las variantes de trabajo existentes en el repositorio.

| Carpeta | Contenido y estado |
|---|---|
| despliegue-portable | Generación por inventario, esquema MySQL, instalación por nodo y servicios de portal, DTI, DHCP, LMS, Notas y Administración. Base anterior al cambio multitabla. |
| actualizacion-multitabla | Versión R1/R2 de Matt: tablas 0/10/20/30 en sw2, permisos individuales R2 y verificación de reglas efectivas. |
| archivo-vnrt-20261023 | Código original y unidades systemd recuperados del respaldo anterior al Lab 5; referencia histórica con sus direcciones originales. |
| variantes/paola | Copia de su código publicado en respaldo-paola-vnrt-20261024; integración pendiente de revisión conjunta. |
| variantes/r5-v1 | Componente publicado en r5-mitigacion-v1: mitigación, adaptador Floodlight y tests simulados; no equivale a R5 desplegado con Suricata. |
| pruebas/r2 y mediciones/r2 | Instrumentos configurables y resultados históricos, distinguidos de pruebas de carga pendientes. |
| respaldo | Guía de reconstrucción, dependencias, procedencia, hashes y comprobaciones de la entrega. |

La referencia de reconstrucción de Matt es despliegue-portable + actualizacion-multitabla. Las variantes no se mezclan automáticamente. Empezar por [la guía de reconstrucción](respaldo/GUIA_RECONSTRUCCION.md).

No se consiguió conexión al controller para una captura nueva el 02/11. Por ello, esta rama conserva fuentes disponibles y el respaldo anterior al Lab 5, no certifica el estado vivo del VNRT en esa fecha. No modifica main ni despliega cambios en máquinas.

El respaldo completo de ocho nodos y el SQL real se conservan cifrados fuera del repositorio. Esta rama no publica credenciales, claves privadas, cookies, sesiones ni datos de cuentas. El JAR de Floodlight y las imágenes del sistema se gestionan como dependencias externas. No es una imagen de disco de las VM. Las pruebas funcionales históricas no sustituyen una prueba integral de recuperación en el nuevo VNRT.

## Datos de red anonimizados

Esta edición pública sustituye direcciones internas por las redes de documentación 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24; las MAC y los DPID reales también se sustituyeron. Los identificadores aquí son ejemplos y no permiten reconectar al VNRT original. Completar el inventario propio antes de generar o instalar. La copia original íntegra se conserva únicamente en el respaldo privado local. Los hashes de archivos publicados corresponden a esta edición; no se afirma identidad byte a byte con el código remoto original.
