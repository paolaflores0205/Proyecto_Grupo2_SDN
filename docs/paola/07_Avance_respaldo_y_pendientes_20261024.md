# Avance real del respaldo y siguientes pasos

Objetivo acordado: liberar el slice de Paola para ONOS/Lab5 y continuar el proyecto en el slice de Matthew, integrando cambios sin sobrescribir su variante R2.

## Completado

Los ocho archivos y sus .sha256 se descargaron en `Proyecto/Respaldos_privados_VNRT/campana_20261024/`. El usuario ejecutó el verificador conjunto y obtuvo 8/8 correctos. La exportación de código volvió a verificar los ocho archivos antes de extraerlos. No se imprimieron contenidos privados.

| Nodo | Archivo verificado |
|---|---|
| controller | controller-20261024T142128115029Z.tar.gz |
| h1 | h1-20261024T204227650106Z.tar.gz |
| h2 | h2-20261024T204413809851Z.tar.gz |
| h3 | h3-20261024T142515196974Z.tar.gz |
| h4 | h4-20261024T142727791493Z.tar.gz |
| sw1 | sw1-20261024T203649304631Z.tar.gz |
| sw2 | sw2-20261024T203907955952Z.tar.gz |
| sw3 | sw3-20261024T204032239229Z.tar.gz |

Los hashes completos y nombres están en el recibo privado VERIFICACION_LOCAL.json y en cada archivo .sha256. Los horarios de captura son distintos; no es un snapshot simultáneo de todas las VM. Se detuvieron los servicios del proyecto para respaldar controller/h3/h4. Switches y clientes solo se consultaron. No se ejecutó limpieza ni cambios de controladores/IP.

Se exportaron 55 archivos Python, además de HTML/CSS y procedencia, a `Proyecto/Codigo_Paola_para_integrar_Matt_20261024/`. Se comprobó sintaxis y se buscó en la exportación la presencia literal de contraseñas/secretos conocidos de los JSON privados: no hubo coincidencias. No se exportaron config.json, claves ni SQL. Esta revisión limitada no detecta secretos desconocidos; el contenido aún se revisa antes de publicar.

## Alcance y límites

El modo project-only conserva la instalación activa y datos del proyecto, pero excluye copias históricas Floodlight de /root y /home/ubuntu. No borrarlas suponiendo que están respaldadas. Tampoco es una imagen completa de VM: no incluye cualquier archivo arbitrario ni todas las cuentas/paquetes binarios. Inventario, lista de paquetes y configuraciones están guardados, pero restaurar un entorno requiere verificarlos.

El primer intento de controller falló por una interpretación incorrecta de SHOW CREATE USER. Se corrigió el script; el respaldo verificado es el del segundo intento. El inventario de ese segundo intento refleja servicios ya detenidos, no su estado activo previo. MySQL seguía activo. No confundir este incidente con pérdida de datos.

## Pendiente antes de limpiar

1. Guardar una segunda copia privada en otro medio o ubicación protegida y verificarla. No subir los tar.gz a GitHub.
2. Clonar el repositorio del proyecto y comparar su estructura/código, sin modificar la rama principal ni hacer push automático.
3. Preparar el commit revisable de Paola, distinguiendo código de despliegue, mediciones y documentación.
4. Deshabilitar el arranque del proyecto, liberar los controladores/reglas para Lab5 y revisar la IP de datos de h1/h2 si se retira DHCP.
5. Comprobar disco: antes de respaldar controller quedaron 477 MiB libres tras apt-get clean; el respaldo local ocupa espacio adicional. ONOS requiere el espacio indicado por el previo. No hay una medida actual después de todos los respaldos.

La integración en Matthew no exige mantener instalado el proyecto en Paola una vez verificado y preservado lo necesario. Sí requiere inventariar el slice de Matthew y comparar su implementación antes de aplicar los cambios. La restauración completa aún no se ha ensayado.

## Cambios prioritarios para comparar con Matthew

- Renovación de identidad y permisos por POST sin retirar previamente las reglas vigentes.
- Normalización de network_state a revoked para sesiones revocadas y protección del UPDATE ACTIVE contra revocación/vencimiento concurrente.
- Logging moderado de Floodlight mediante logback y drop-in systemd, adaptado a sus rutas y servicio.
- Scripts de activación, continuidad, logout y concurrencia; adaptar inventario/trust antes de ejecutar.
- No reemplazar su pipeline o permisos compartidos por el generador de Paola: revisar las diferencias de R2 primero.

Mejoras futuras de roles compartidos, renovación y capacidad están documentadas en 06_Detalle_multitable_y_mejoras.md; siguen siendo propuestas, no cambios desplegados.
