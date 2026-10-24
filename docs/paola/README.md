# Guardar el proyecto y usar el slice para Lab5

Preparado el 24 de octubre de 2026 para Paola, Grupo 2.

**No se ha realizado ningún push ni se ha limpiado el slice.** Las herramientas de este paquete ya se ejecutaron en los ocho nodos y se verificaron las copias descargadas en Windows. La carpeta SDN no es un repositorio Git. El repositorio de Lab4 es otro proyecto y no debe usarse para guardar R1/R2.

Repositorio indicado por Paola: <https://github.com/paolaflores0205/Proyecto_Grupo2_SDN.git>.

**Actualización del objetivo acordada por chat:** el proyecto continuará en el slice de Matthew. El slice de Paola se libera para Lab5. La guía 05 queda como recuperación de contingencia, no como obligación de volver a instalar el proyecto en su slice. Antes de desplegar en Matthew, comparar su código R2 e inventario: un pull no adapta MAC/DPID/puertos ni aplica servicios automáticamente.

**Avance real del respaldo por chat:** los ocho archivos privados están en `../Respaldos_privados_VNRT/campana_20261024/` y el verificador informó 8/8 correctos. Además, las carpetas vivas del portal y DTI se copiaron por separado. El adaptador del portal coincide con la copia corregida del 22/10 (9277 bytes); DTI contiene una copia distinta de 8960 bytes, conservada por procedencia. Se exportó código revisable a `../Codigo_Paola_para_integrar_Matt_20261024/`. Ver `07_Avance_respaldo_y_pendientes_20261024.md` para el alcance y los pendientes.

## Orden de lectura y ejecución

1. `01_Estado_del_proyecto_y_decisiones.md`: qué construimos, qué probamos, qué corregimos y qué proponemos.
2. `02_Respaldo_privado_antes_de_Lab5.md`: respaldar los ocho nodos y verificar las copias fuera del slice. Este paso va antes de limpiar.
3. `03_Git_y_push_manual.md`: exportar código revisable, conservar evidencia seleccionada y hacer el push personalmente.
4. `04_Pausar_proyecto_para_Lab5.md`: desactivar los servicios que podrían volver a programar flujos, liberar control de los switches y comprobar disco.
5. `05_Restaurar_y_activar_el_proyecto.md`: volver al proyecto después del laboratorio, con comandos y verificaciones.

El previo revisado es `Labs/Lab5/TEL354_INFORME_PREVIO_LAB5_2026-2.docx`. Pide ONOS 2.7.0 en Docker, control por ens3 fuera de banda y un reset al finalizar. Su Actividad 0 parte de un slice con Lab4; nuestro slice contiene además servicios del proyecto. No basta con matar el proceso Java: systemd puede reiniciarlo y el adaptador puede reinstalar flujos.

Hay dos respaldos distintos:

- **Git:** código, documentación y resultados sin secretos, útiles para trabajar en equipo.
- **Respaldo privado:** dump SQL, cuentas SQL, claves TLS, secretos de aplicación, configuraciones y programas exactos de las VM. Permite recuperar el estado del proyecto; no se sube a Git, ni siquiera a un repositorio privado.

El respaldo de archivos no es una imagen completa de las VM. Si VNRT ofrece snapshot/exportación, usar también esa función y guardar su identificador. Verificar que cubra discos y configuración del slice; no asumir que existe o que incluye todos los nodos.

## Primera acción

Leer `02_Respaldo_privado_antes_de_Lab5.md`, comprobar el acceso a controller y ejecutar el inventario inicial. No empezar por los comandos destructivos de la Actividad 0.

Los scripts se probaron con datos sintéticos y después se ejecutaron realmente para respaldar los ocho nodos. La restauración sigue sin ensayarse. Si un paso falla, detenerse, conservar los originales y revisar la salida sin publicar secretos.

## Verificación local realizada

Incidente durante el primer respaldo real de controller: SHOW CREATE USER devolvió una columna y el script esperaba dos, provocando IndexError antes de generar un archivo válido. No se borraron datos; los servicios sdn-* ya estaban detenidos. Se corrigió el parser para aceptar una sentencia CREATE USER única en una o varias columnas, sin publicar su contenido, y se añadió inventario previo persistente para futuros intentos fallidos. Antes del primer intento, los seis servicios del controller estaban activos según las salidas registradas; el inventario de un reintento refleja la pausa ya efectuada.

**Controller respaldado y verificado realmente:** `controller-20261024T142128115029Z.tar.gz`, aproximadamente 85 MB, descargado con su .sha256 en `../Respaldos_privados_VNRT/campana_20261024/`. SHA256 `551ef043e3e89f01d51a729846fb8e806afbabd89f1ee5c3658566a1d4b0b55c`. El generador verificó la copia en controller y se repitió `inspect_archive` sobre el archivo descargado en Windows: integridad externa/interna y componentes esenciales correctos. También se verificaron los otros siete nodos. Alcance `--project-only`: no incluye las copias históricas Floodlight excluidas. En el último estado reportado, los servicios sdn-* de controller/h3/h4 quedaron detenidos pero aún no deshabilitados; MySQL no se detuvo. La segunda copia privada, el push y la limpieza siguen pendientes. La restauración aún no se ha ensayado.

El 24/10 se ejecutó `scripts/autoprueba_local.py`: sintaxis de los cinco scripts correcta, ocho respaldos artificiales verificados, exportación selectiva de código sin config.json/claves/SQL, detección de checksum externo incorrecto y de alteración interna con checksum externo recalculado. No se utilizaron datos reales ni SSH. Esto no demuestra la restauración de las VM ni sustituye la comprobación de los respaldos reales.

Las utilidades de respaldo/verificación usan Python 3.11 o posterior (`hashlib.file_digest`); comprobar `python3 --version` en las VM. La copia de referencia del proyecto utiliza Ubuntu 24/Python 3.12. La herramienta de datos de cliente necesita `python3-yaml`, ya usado por el instalador del proyecto.
