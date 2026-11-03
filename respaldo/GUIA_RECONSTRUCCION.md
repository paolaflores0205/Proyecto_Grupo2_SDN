# Reconstrucción en un VNRT nuevo

## Elegir la referencia

La referencia funcional de Matt es Floodlight con R1/R2 multitabla: base portable más actualizacion-multitabla. El contenido de variantes/paola y variantes/r5-v1 conserva avances separados; no sustituye automáticamente esta referencia. R5 dispone de tests simulados y adaptador, pero no está integrado ni validado de extremo a extremo con Suricata en esta maqueta.

## Preparar la infraestructura

Inventariar las nuevas VM, interfaces de gestión/datos, MAC, DPID, ofports y enlaces. Los roles lógicos son controller, sw1, sw2, sw3, h1, h2, h3 y h4. Mantener la administración fuera de los bridges de datos y verificar acceso por consola. Si agregan switches o recursos, ampliar primero el modelo y el catálogo: los scripts actuales no descubren ni admiten automáticamente cualquier topología.

Paquetes del sistema: Java compatible con el JAR de Floodlight elegido, Python 3 y venv, MySQL, Open vSwitch en switches, Kea DHCP en controller, OpenSSL y herramientas de diagnóstico. Las dependencias Python se enumeran en requirements-controller.txt; la guía del instalador especifica los paquetes APT. La memoria y el disco deben medirse en las nuevas VM antes de desplegar. No levantar simultáneamente ONOS y Floodlight sobre el puerto 6653.

## Instalar la base

1. Leer despliegue-portable/README.md, GUIA_DESPLIEGUE.md y VALIDACION.md. Completar una copia privada de topology.example.json con el inventario nuevo y confirmar su contenido.
2. Obtener el JAR de Floodlight por un canal de dependencias del grupo o desde el proyecto oficial https://github.com/floodlight/floodlight y registrar versión/hash. No se incluyó el binario; las licencias y avisos están en despliegue-portable/vendor. La compatibilidad del parser de metadata debe comprobarse con esa compilación.
3. Ejecutar prepare.py conforme a su ayuda para generar el paquete de destino; transferirlo a cada nodo. Usar install_node.py según el rol. El orden y argumentos están en GUIA_DESPLIEGUE.md. El instalador cambia configuración del nodo y no debe apuntarse al gateway.
4. El esquema MySQL es despliegue-portable/schema.sql. seed_database.py crea cuentas de prueba nuevas, contraseñas, secretos y configuración privada: no copiar las sesiones o credenciales de una VM vieja. Los certificados y claves TLS se regeneran para las direcciones nuevas. Proteger los archivos privados fuera del repositorio.
5. Verificar la base antes del cambio multitabla. Copiar los tres módulos actualizacion-multitabla/source y ejecutar el instalador de esa carpeta con cero sesiones activas. Este paso crea la revisión de política y los triggers; no basta importar solamente schema.sql.

## Comprobar

En controller: comprobar mysql, sdn-dhcp, sdn-floodlight, sdn-r1, sdn-portal y sdn-admin. En h3 comprobar LMS; en h4, Notas y recurso administrativo. Consultar los tres switches y sus reglas OpenFlow13. Abrir el portal antes de login, probar cada rol, LMS/Notas/Administración y revocación.

En esta topología: 48 reglas propias base; 19 en sw1, 20 en sw2 y 9 en sw3. sw2 usa tablas 0/10/20/30 y sw3 tabla 0. El crecimiento es 4 reglas por sesión y 4 por permiso privilegiado; las reglas internas del controlador se cuentan aparte. Los tests y sus ejemplos están en pruebas/r2; la campaña histórica está en mediciones/r2.

No copiar unidades systemd históricas sobre el destino sin ajustar direcciones, caminos y precedencia de drop-ins. No importar OVSDB, Netplan o esquemas del sistema MySQL de otra VM de forma indiscriminada. El respaldo privado permite recuperar datos anteriores si fuera necesario, pero no es una imagen arrancable ni un despliegue validado en la infraestructura nueva.

## Datos de red anonimizados

Esta edición pública sustituye direcciones internas por las redes de documentación 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24; las MAC y los DPID reales también se sustituyeron. Los identificadores aquí son ejemplos y no permiten reconectar al VNRT original. Completar el inventario propio antes de generar o instalar. La copia original íntegra se conserva únicamente en el respaldo privado local. Los hashes de archivos publicados corresponden a esta edición; no se afirma identidad byte a byte con el código remoto original.
