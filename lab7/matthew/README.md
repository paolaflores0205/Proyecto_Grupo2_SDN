# Entrega Lab 7 — Matthew Salvador (R1 / R2)

## Estado de la entrega
- **Fase A (local, aislada, sin modificar VNRT): COMPLETADA (22/11/2026).**
  - Versión de partida en `app` congelada con hashes SHA-256 (`evidencias/version_partida_sha256.json`).
  - Paquete compartido `codigo/access/` unificado con adaptadores MySQL parametrizados, bloqueo `N=8/900 s` por cuenta y terminal, vinculación de consola DTI (`admin_accounts`) y traductor del pipeline multitabla real (`sw2` tablas `0/10/20/30` + `sw1`/`sw4` + `sw3`, `DENY_PRIORITY=550`).
  - Módulos de integración listos para despliegue en `codigo/integracion/` (`vnrt_portal_paso5.py`, `vnrt_mt_adapter.py`).
  - **26/26 pruebas PASS** (`0 FAIL`, `0 SKIPPED`), cobertura medida con `trace`: **95.4 %** sobre 651 líneas en `access/`.
- **Fase B (ventana de integración en VNRT): COMPLETADA (22/11/2026).**
  - Despliegue en `app:/opt/sdn-portal-paso4/` (respaldo en `/opt/sdn-portal-paso4.bak-lab7/`), **26/26 PASS** directamente en `app` (`resultados/unittest_app_fase_b.txt`).
  - Integración representativa en vivo (`evidencias/integracion_vnrt_fase_b.json`): matriz de 4 roles + `logout`, bloqueo `N=8/900 s` por cuenta (`h1+h2` → `HTTP 429`), revocación selectiva DTI de `h2` manteniendo `h1` en LMS y Notas (`HTTP 200`), y limpieza total (`0` sesiones activas, `0` reglas individuales, `98` reglas base).

## Estructura de esta carpeta
```text
lab7/matthew/
  codigo/
    access/         Paquete unificado R1/R2 compartido entre portal, adaptador y tests
    integracion/    Versiones integradas de vnrt_portal_paso5.py y vnrt_mt_adapter.py
    tests/          Suite de 26 pruebas (R1-01 a R2-03, concurrencia, DTI, SQL, multitabla)
  resultados/
    unittest_matthew_r1_r2.txt    Salida original completa de unittest (stdout/stderr/exit code)
    coverage_trace_r1_r2.txt      Reporte de cobertura por modulo con python -m trace
    resumen_ejecucion.json        Resumen estructurado de ejecucion y cobertura
  evidencias/
    version_partida_sha256.json   Hashes SHA-256 de partida en app + servicios systemd + hashes Lab 7
    registro_evidencia_comun.json Registro comun de evidencia (esquema oficial de la guia HTML)
    fichas_casos_lab7.md          Fichas completas de los 6 codigos obligatorios (R1-01 a R2-03)
  diseno.md         Tecnologias, despliegue, cadena de llamadas, APIs, diagrama y cambios
  casos.csv         Tabla trazable de los 26 casos (X.Y.Z, codigo, funcion, entrada, esperado, obtenido)
  README.md         Este archivo
```

## Comandos reproducibles (Fase A)
Desde `lab7/matthew/codigo/`:
```powershell
# Ejecutar toda la bateria de pruebas unitarias e integracion simulada (Windows):
py -m unittest discover -s tests -t . -v

# Medir cobertura de lineas con trace (sin dependencias externas):
py -m trace --count --summary --missing -C ..\resultados\.cover --module unittest discover -s tests -t .
```
En `app` (Linux): reemplazar `py` por `python3`.

## Resumen de resultados obtenidos (Fase A + Fase B)
- **Pruebas ejecutadas:** 26 | **PASS:** 26 | **FAIL:** 0 | **Omitidas:** 0 (`1.211 s` en corrida local final con `trace`; `6.744 s` en producción en `app` importando `/opt/sdn-portal-paso4/access/`).
- **Cobertura (`trace`, líneas ejecutadas en `codigo/access/`):**
  - `access.__init__`: 100 % (9 líneas)
  - `access.auth`: 100 % (29 líneas)
  - `access.lockout`: 100 % (71 líneas)
  - `access.translate`: 97 % (271 líneas)
  - `access.dti`: 96 % (52 líneas)
  - `access.passwords`: 96 % (33 líneas)
  - `access.authz`: 95 % (87 líneas)
  - `access.mysql_adapters`: 85 % (99 líneas)
  - **Total ponderado en `access/`:** ~95.4 % sobre 651 líneas. *(Los wrappers Flask/daemon de producción fueron validados en vivo durante la Fase B).*
