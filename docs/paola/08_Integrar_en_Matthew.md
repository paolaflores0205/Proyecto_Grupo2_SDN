# Integrar los avances de Paola en el slice de Matthew

Este documento es un plan de integración, no una orden para reemplazar el despliegue actual. La versión viva de Matthew aún no se inventarió ni se comparó. El contenido de main inspeccionado corresponde al paquete histórico de tabla única, no necesariamente a lo que Matthew tiene funcionando hoy.

## 1. Identificar qué debe compararse

El adaptador activo respaldado de Paola está en `vnrt-paola-20261024/controller/opt/sdn-portal-paso4/vnrt_avz7_adapter.py`. La copia con el mismo nombre en sdn-admin-paso7 es distinta; no usarla como última versión por accidente.

Cambios concretos de Paola:

1. Al renovar identidad y permisos, retirar solo nombres obsoletos: `red.remove([n for n in stale if n not in names])`. Las reglas vigentes se actualizan por POST. El nombre de las reglas debe ser estable para que esto funcione en la versión de Matthew.
2. Para filas ya revocadas, normalizar tanto session_state como network_state: REVOKED/revoked.
3. Al actualizar ACTIVE, exigir `revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)` para no sobrescribir una revocación o vencimiento con un estado esperado antiguo.
4. Instrumentos de activación, continuidad, logout y concurrencia de h1/h2.
5. Configuración de logs moderada de Floodlight. Su definición exacta se conserva en el respaldo privado; al adaptarla usar las rutas de Matthew.

El pipeline de Paola usa identidad por terminal y permisos por terminal–recurso. Si Matthew implementó reglas compartidas, adaptar estos cambios a sus nombres, propiedad de reglas y verificación. No copiar íntegramente el generador de Paola sobre el suyo.

## 2. Inventariar el controller de Matthew sin modificarlo

En su controller, con su autorización y credenciales:

```bash
hostname
ip -br address
df -h /
systemctl is-active sdn-floodlight sdn-r1 sdn-portal sdn-admin sdn-dhcp mysql
sudo systemctl cat sdn-r1
sudo systemctl cat sdn-floodlight
sudo sha256sum /opt/sdn-portal-paso4/vnrt_avz7_adapter.py
```

Si los paths o nombres difieren, leer su configuración real antes de continuar. No publicar archivos config.json ni claves. En switches, consultar ovs-vsctl show y ovs-ofctl -O OpenFlow13 show/dump-flows para su bridge real. Guardar copias privadas e inventario antes de cambiar nada.

## 3. Preparar una integración revisable

Comparar el adaptador, el generador, el módulo de contexto/topología y sus verificaciones. Separar los cambios de lógica de los valores particulares del inventario. No reutilizar los ejemplos de red de este repositorio ni los secretos de Paola como configuración real.

Mantener una copia de la versión funcional de Matthew y preparar el archivo candidato fuera de la ruta activa. Validar sintaxis y mostrar el diff. Si el esquema de network_rules o el formato de nombres cambió, resolver esa compatibilidad antes de instalar. Git pull no actualiza automáticamente /opt ni systemd.

No cambiar simultáneamente permisos compartidos, temporizadores y otras políticas nuevas: primero integrar las correcciones necesarias, probar y luego evaluar optimizaciones.

## 4. Aplicar y probar en una ventana acordada

Solo después de la comparación y respaldo: instalar el candidato preservando propietario/permisos y reiniciar el servicio afectado. El nombre exacto y los comandos de instalación se definen con el inventario de Matthew, no se adivinan aquí.

Verificaciones mínimas:

- Antes del login: portal disponible y recursos protegidos inaccesibles, contrastados con reglas.
- Login válido y recursos permitidos/denegados por rol.
- Sesión mantenida por encima de la vigencia de reglas: observar renovación.
- Logout con ausencia de sesión vigente y retiro efectivo en SQL/OVS/tráfico.
- Misma cuenta en dos terminales: revocar uno y conservar el otro.
- Vencimiento, cambio de rol y deshabilitación: revisar el alcance de retiro esperado.
- Coherencia de estados: no terminar REVOKED/active; confirmar además el dataplane.
- Fallo/reinicio del adaptador/controlador según el diseño, manteniendo la gestión SSH.

Conservar fecha, versiones y resultados nuevos. Las mediciones de Paola no validan el nuevo despliegue. Si una prueba falla, volver a la copia funcional del servicio y revisar la causa antes de ampliar el cambio.

## 5. Qué sigue siendo futuro

Compartir permisos por rol, modificar el mecanismo de renovación y determinar capacidad son propuestas descritas en 06_Detalle_multitable_y_mejoras.md. No presentarlas como parte de esta captura ya implementada.
