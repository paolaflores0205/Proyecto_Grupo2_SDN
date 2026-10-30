# Pruebas de R2

Desde la raíz del repositorio, pruebas locales que no se conectan al VNRT:

```bash
python pruebas/r2/test_catalogo.py
python mediciones/r2/test_resumen.py
```

El catálogo reconstruye la dependencia legacy como lo hace `despliegue-portable/prepare.py` y usa direcciones ficticias de documentación. Comprueba conteos, separación de contextos, reglas de sesión/R2 y rechazo de instrucciones alteradas. No valida la API de un controlador remoto.

## Preparar pruebas remotas

Instalar `python -m pip install -r pruebas/r2/requirements.txt`. Copiar `config.example.json` a un archivo privado `config.local.json` en el directorio de ejecución y sustituir host SSH, puertos, IP, URL y rutas CA según el inventario real. No copiar `topology.fixture.json` al VNRT.

Variables: `VNRT_TEST_CONFIG` = ruta de ese JSON; `VNRT_TEST_OUTPUT` = carpeta privada de resultados; `VNRT_SSH_PASSWORD` si SSH usa contraseña; `VNRT_SUDO_PASSWORD` para las órdenes privilegiadas. Se admite `ssh.key_filename` en el JSON para SSH por clave; no colocar la clave en el repositorio. Confirmar previamente las huellas SSH y guardarlas en known_hosts: los scripts rechazan hosts desconocidos. Los certificados CA deben corresponder a los nombres/IP reales.

`network.test_accounts_path` es un archivo privado del controller con lista de objetos `{role, username, password}` para los cuatro roles. `network.dti_accounts_path` es otro archivo privado con `{username,password}`. No se incluyen cuentas reales. Los campos de configuración denominan rutas; no contienen contraseñas.

En un entorno de prueba sin sesiones activas y con matriz inicial docente/Notas permitida:

```bash
python pruebas/r2/pruebas.py --ejecutar --full
python pruebas/r2/pruebas_consistencia.py --ejecutar
```

Estas pruebas modifican permisos, crean/cierra sesiones, fuerzan vencimiento e interrumpen temporalmente `sdn-r1` en la prueba de consistencia. Esta última inyecta fallos y la recuperación puede retirar reglas de todas las sesiones. El código presupone rutas Linux estándar del despliegue base, base `sdn_g2`, sudo y MySQL por socket en controller. Mantiene los ocho nodos lógicos de la maqueta; no es un descubridor de topologías arbitrarias.

Al terminar comprobar servicios activos, cero sesiones de prueba y reglas retiradas; si una prueba se interrumpe, revisar y cerrar las sesiones que dejó antes de repetir. Los resultados pueden contener detalles de entorno y se mantienen privados por defecto. No ejecutar las dos campañas simultáneamente.

Los JSON de `resultados-historicos/` son extractos de comprobaciones booleanas del VNRT original del 21 de octubre, no registros de ejecución de este paquete adaptado. La matriz original registró 24 comprobaciones del orquestador y consistencia 8; esto no equivale a 24/8 repeticiones de rendimiento.
