# Actualización multitabla R1 R2

Este paquete es una actualización del despliegue portable `VNRT_R1_R2_PORTABLE_20261010`, no un instalador completo ni un respaldo del VNRT. Requiere la versión R1/R2 anterior funcionando, con sus dependencias, base, cuentas, certificados y servicios. No contiene contraseñas, claves privadas, SQL de usuarios ni el JAR.

No ejecutar sobre otro entorno sin inventario, respaldo privado y consola de recuperación. El instalador rechaza el cambio si detecta sesiones vigentes; acordar primero el cierre de las sesiones de prueba. No modifica gateway, Netplan, SSH ni la matriz de permisos. No implementa R5.

## Integración en otro VNRT

1. Leer esta guía y `GUIA_TECNICA.md`. Confirmar que el despliegue anterior funciona y que la configuración de red propia ya fue generada con su inventario. Mantener los módulos anteriores: son dependencias y permiten recuperar.
2. Guardar un respaldo privado de código, configuración, unidades systemd y base, sin publicarlo. Confirmar que existe acceso de recuperación independiente.
3. Copiar los tres archivos `source/vnrt_mt_*.py` a `/opt/sdn-portal-paso4/`, propiedad root y modo 0644. Copiar `instalar_controller.py` a una ruta administrativa del controller. No es necesario transferir las evidencias del VNRT de Matt.
4. Comprobar en tablas aisladas que esta versión de Floodlight acepta `instruction_write_metadata`, coincidencias en metadata y `instruction_goto_table`. No basta recibir una respuesta REST exitosa: comprobar las instrucciones realmente instaladas.
5. Confirmar que no hay sesiones vigentes y ejecutar localmente en controller, como administrador: `sudo python3 instalar_controller.py cutover`. Genera la revisión de política y triggers MySQL, comprueba la base, selecciona los módulos nuevos con drop-ins y arranca adaptador/portal. Si falla el cambio inicial, intenta recuperar la base anterior. Guardar la salida.
6. Comprobar acceso sin sesión, cuatro roles, ida/retorno, revocación selectiva, dos sesiones independientes, revisión obsoleta, expiración y arranque. La validación de Matt no demuestra que el entorno de destino ya fue probado.
7. Para recuperar el procesamiento anterior: `sudo python3 instalar_controller.py rollback`. Conserva los datos actuales y no restaura sesiones antiguas. El módulo anterior `vnrt_avz7_red.py` debe estar presente.

## Direcciones y puertos diferentes

Los módulos usan el inventario `HOSTS` y los enlaces `ADJ` de la versión anterior. Si se instaló el paquete portable original, su contexto generado proporciona direcciones, MAC, DPID, ofports y subred. No sustituir el archivo generado con la configuración de Matt. El bind del portal se obtiene del inventario. No se agregan VLAN ni metadata entre switches.

La subred se exige en la configuración portable `data_cidr`; no hay una subred privada de respaldo implícita. Este paquete presupone los nombres lógicos controller, sw1, sw2, sw3, h1, h2, h3 y h4 y la misma topología lógica. No admite automáticamente topologías arbitrarias, usuarios Linux diferentes ni más clientes.

## Resultado y límites

sw2 usa tablas 0/10/20/30; sw3 permanece en tabla 0. LMS utiliza políticas compartidas habilitadas por la clasificación de sesión; Notas y Administrativo conservan cuatro entradas por permiso privilegiado. La revisión de autorización es global y conservadora. Las renovaciones siguen siendo DELETE/ADD; no se afirma una reducción de operaciones ni una capacidad máxima validada.

Esta actualización se probó funcionalmente en el VNRT de Matt. No fue desplegada en el VNRT de los compañeros. Consultar `GUIA_TECNICA.md` y repetir pruebas propias antes de anunciar que está verificada.
