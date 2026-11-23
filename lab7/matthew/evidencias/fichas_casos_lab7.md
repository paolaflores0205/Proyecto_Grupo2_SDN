# Fichas de Casos de Prueba Obligatorios (R1-01 a R2-03) — Lab 7 (Matthew)

> **Alcance de esta ejecución (Fase A — 22/11/2026):** 26/26 pruebas ejecutadas en modo aislado (unitarias + integración local con Werkzeug + integración simulada contra SQL/DTI/OVS). **0 FAIL, 0 SKIPPED.** Cobertura de líneas en `access/` medida con `python -m trace --count --summary --missing`: **95.7 % ponderado** (648 líneas ejecutables). Las pruebas de integración real sobre VNRT (`Fase B`) se agregarán al abrir la ventana coordinada del grupo.

## Matriz de Trazabilidad (Códigos Obligatorios de Matthew)

| Código obligatorio | Casos `X.Y.Z` | Función real validada | Tipo | Resultado (Fase A) | Evidencia |
|---|---|---|---|---|---|
| **R1-01** | `1.1.1`, `1.1.3`, `1.1.4`, `1.1.7`, `1.1.8` | `access.auth.validate_credentials()`, `access.passwords.verify_password()`, `access.mysql_adapters.MySQLUserStore` | Unitaria / Integración Werkzeug / Simulada SQL | **PASS** (5/5) | `resultados/unittest_matthew_r1_r2.txt` |
| **R1-02** | `1.1.2`, `1.1.5`, `1.1.6`, `1.1.8` | `access.auth.validate_credentials()`, `access.passwords.verify_password()`, `access.mysql_adapters.MySQLUserStore` | Unitaria (Inválido) / Simulada SQL | **PASS** (4/4) | `resultados/unittest_matthew_r1_r2.txt` |
| **R1-03** | `1.2.1` a `1.2.7` | `access.lockout.LoginGuard`, `access.mysql_adapters.MySQLFailureStore` | Unitaria (Límite, Normal, Falso positivo, Concurrencia) / Simulada SQL | **PASS** (7/7) | `resultados/unittest_matthew_r1_r2.txt` |
| **R2-01** | `2.1.1`, `2.1.3`, `2.1.4`, `2.1.5`, `2.1.6` | `access.authz.evaluate_access()`, `access.dti.evaluate_dti_console_access()`, `access.mysql_adapters.load_access_matrix_from_rows()` | Unitaria / Simulada DTI y SQL | **PASS** (5/5) | `resultados/unittest_matthew_r1_r2.txt` |
| **R2-02** | `2.1.2`, `2.1.4`, `2.1.6` | `access.authz.evaluate_access()` | Unitaria (Límite) / Simulada SQL | **PASS** (3/3) | `resultados/unittest_matthew_r1_r2.txt` |
| **R2-03** | `2.2.1` a `2.2.5` | `access.translate.translate_policy()`, `access.translate.effective_table20_decision()` | Unitaria / Simulada Multitabla y Failover | **PASS** (5/5) | `resultados/unittest_matthew_r1_r2.txt` |

---

## Ficha 1 — `1.1.1` / `R1-01`: Autenticación de usuarios activos por rol

- **Número y nombre:** `1.1.1` (y complementarios `1.1.3`, `1.1.4`, `1.1.7`, `1.1.8`) — Código obligatorio **R1-01** — Función real: `access.auth.validate_credentials()` + `access.mysql_adapters.MySQLUserStore.get_user()`.
- **Tipo y objetivo:** Prueba unitaria (normal/límite) e integración local con Werkzeug / SQL simulado. Verificar que todo usuario activo de los 4 roles reales (`estudiante`, `docente`, `administrativo`, `visitante`) obtenga su `user_id` y código de rol, normalizando espacios/mayúsculas y verificando hashes `scrypt`/`pbkdf2` de Werkzeug; y que un usuario desactivado (`active=False`) sea rechazado.
- **Prerrequisitos:** Paquete `codigo/access/` (SHA-256 registrado en `evidencias/version_partida_sha256.json`), `MemoryUserStore`, `FakeMySQLCursor` y `werkzeug.security`. Sin credenciales reales de producción.
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r1_01_02_validate_credentials -v` desde `lab7/matthew/codigo/`.
- **Resultado esperado:** `AuthResult(ok=True, user_id, role)` para `est01`, `doc01`, `adm01`, `vis01` y `"  DOC01 "`; `ok=False` con mensaje uniforme para `baja01`; consulta parametrizada `WHERE u.username = %s`; compatibilidad total con Werkzeug `scrypt` y `pbkdf2`.
- **Resultado obtenido:** **PASS** (5/5 casos). Los 4 roles retornaron `(id, role)` exactos; `"  DOC01 "` normalizó a `docente`; `baja01` fue rechazado con `GENERIC_ERROR`; Werkzeug `scrypt` y `pbkdf2` validados; `MySQLUserStore` ejecutó 2 consultas parametrizadas con `%s`.
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `resultados/coverage_trace_r1_r2.txt` (`access.auth`: 100 %, `access.passwords`: 96 %), `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** Valida R1 (autenticación contra repositorio de usuarios y roles). No involucra MySQL ni HTTPS en vivo en esta fase (Fase B).

---

## Ficha 2 — `1.1.2` / `R1-02`: Rechazo uniforme ante credenciales inválidas e inyección SQL

- **Número y nombre:** `1.1.2` (y complementarios `1.1.5`, `1.1.6`, `1.1.8`) — Código obligatorio **R1-02** — Función real: `access.auth.validate_credentials()` + `access.passwords.verify_password()`.
- **Tipo y objetivo:** Prueba unitaria (inválido). Comprobar que contraseñas erróneas, usuarios inexistentes, campos vacíos, `None`, cadenas > 256 caracteres, intentos de inyección SQL (`' OR '1'='1`, `est01' --`, `DROP TABLE`) y hashes dañados se rechacen sin lanzar excepciones, con un mensaje único que no revele existencia de cuenta y sin asignar rol.
- **Prerrequisitos:** `MemoryUserStore` con registro de consultas (`store.lookups`) y `FakeMySQLCursor`.
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r1_01_02_validate_credentials.InvalidCredentials tests.test_r1_01_02_validate_credentials.PasswordHashesAndSQLAdapter -v`.
- **Resultado esperado:** `ok=False`, `user_id=None`, `role=None`, `message == "Usuario o contraseña inválidos."` en los 9 subcasos; `0` consultas al `UserStore` para entradas con caracteres SQLi; `False` sin excepción en 5 formatos de hash corrupto.
- **Resultado obtenido:** **PASS** (4/4 métodos, 14/14 subcasos). `store.lookups == ["noexiste"]` confirmó que ningún payload SQLi llegó a la base de datos.
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** Se mitiga la enumeración de cuentas mediante `DUMMY_HASH` en tiempo constante y validación estricta `[a-z0-9_]{1,64}` antes de tocar SQL.

---

## Ficha 3 — `1.2.1` a `1.2.7` / `R1-03`: Bloqueo `N = 8 / 900 s` por cuenta o terminal, concurrencia y SQL

- **Número y nombre:** `1.2.1` a `1.2.7` — Código obligatorio **R1-03** — Función real: `access.lockout.LoginGuard` (`register_failed_attempt`, `is_locked`, `lock_scope`) + `access.mysql_adapters.MySQLFailureStore`.
- **Tipo y objetivo:** Prueba unitaria (límite, normal, falso positivo, concurrencia) e integración simulada SQL. Verificar umbral exacto `N-1=7` vs `N=8`, vencimiento de ventana de `900 s`, acumulación por cuenta desde dos terminales (`h1`+`h2`), bloqueo por terminal ante *password spraying*, no afectación a terceros (`doc01` en `h2`), ausencia de pérdida de intentos con 12 hilos concurrentes y persistencia en `auth_events` tras reinicio de proceso.
- **Prerrequisitos:** Reloj UTC inyectado (`T0 = 2026-11-22T00:00Z`), `MemoryFailureStore` (`RLock`), `FakeMySQLDatabase`/`FakeMySQLCursor` con `GET_LOCK`/`RELEASE_LOCK`.
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r1_03_lockout -v`.
- **Resultado esperado:** `is_locked=False` en fallo 7; `True` en fallo 8; `False` en `T0+971 s`; bloqueo por cuenta (`4+4=8`) y por terminal (`8` cuentas en `h1`); `failures==12` con 12 hilos; locks deterministas `['sdn-r1-acct-est01', 'sdn-r1-term-192.168.10.1']` y estado persistido al instanciar un nuevo `LoginGuard`.
- **Resultado obtenido:** **PASS** (7/7 casos). Cobertura de `access.lockout`: **100 %** (71/71 líneas).
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `resultados/coverage_trace_r1_r2.txt`, `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** Documenta el cambio de comportamiento frente al portal previo (que solo bloqueaba por terminal). La ejecución real contra `auth_events` en MySQL se realiza en Fase B.

---

## Ficha 4 — `2.1.1`, `2.1.3`–`2.1.6` / `R2-01`: Decisión por rol/recurso y separación de consola DTI

- **Número y nombre:** `2.1.1`, `2.1.3`, `2.1.4`, `2.1.5`, `2.1.6` — Código obligatorio **R2-01** — Función real: `access.authz.evaluate_access()`, `access.dti.evaluate_dti_console_access()`, `access.mysql_adapters.load_access_matrix_from_rows()`.
- **Tipo y objetivo:** Prueba unitaria e integración simulada DTI/SQL. Verificar que `Administrador DTI` obtiene `PERMIT` sobre `consola_dti` y `docente` obtiene `DENY` con motivo; demostrar separación estricta entre el recurso académico `administracion` (`h4:8443`, rol `administrativo`) y `consola_dti` (`192.168.0.20:8443`, `admin_accounts` en red de gestión); validar la matriz completa 4×4 y la vinculación con `identity()`/`authorized()` de `vnrt_admin_paso7.py`.
- **Prerrequisitos:** `build_campus_matrix()`, `DTIAccount`, filas simuladas de `role_permissions`.
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r2_01_02_evaluate_access -v`.
- **Resultado esperado:** `admin_dti -> consola_dti: PERMIT`; `docente -> consola_dti: DENY`; `administrativo -> administracion: PERMIT` y `administrativo -> consola_dti: DENY`; `DTIAccount` activo desde `192.168.0.1` permitido y rechazado desde `192.168.10.1`, inactivo, sin sesión o con IP distinta.
- **Resultado obtenido:** **PASS** (5/5 casos, 16/16 combinaciones de matriz conformes). Cobertura: `access.authz` **95 %**, `access.dti` **96 %**.
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `resultados/coverage_trace_r1_r2.txt`, `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** No abre la red de gestión a clientes de datos; mantiene `admin_accounts` separado de `users`/`roles`.

---

## Ficha 5 — `2.1.2` / `R2-02`: Denegación por defecto para rol o recurso no registrado

- **Número y nombre:** `2.1.2` (y `2.1.4`, `2.1.6`) — Código obligatorio **R2-02** — Función real: `access.authz.evaluate_access()`.
- **Tipo y objetivo:** Prueba unitaria (límite). Comprobar que cualquier rol fuera del registro (`Invitado`) o recurso fuera del inventario (`servidor_x`), así como recursos con `deployment_state != 'active'`, reciban `Decision.DENY` por defecto con motivo explícito.
- **Prerrequisitos:** `build_campus_matrix()` y `load_access_matrix_from_rows()`.
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r2_01_02_evaluate_access.EvaluateAccess.test_2_1_2_unknown_role_or_resource_denied -v`.
- **Resultado esperado:** `(Decision.DENY, "Rol no registrado")` para `("Invitado", "lms")` y `(Decision.DENY, "Recurso fuera del inventario")` para `("docente", "servidor_x")`.
- **Resultado obtenido:** **PASS** (3/3 casos relacionados).
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** Garantiza postura *default-deny* ante entradas no contempladas en MySQL.

---

## Ficha 6 — `2.2.1` a `2.2.5` / `R2-03`: Traducción al pipeline multitabla real y precedencia de `DENY`

- **Número y nombre:** `2.2.1` a `2.2.5` — Código obligatorio **R2-03** — Función real: `access.translate.translate_policy()` y `access.translate.effective_table20_decision()`.
- **Tipo y objetivo:** Prueba unitaria e integración simulada de pipeline multitabla. Verificar que ante `PERMIT` y `DENY` solapados sobre `notas` o `lms` en `sw2` tabla 20, prevalece `DENY` (`priority=550`, `actions=""`, sin `goto_table`) sobre `PERMIT` (`500`/`501`) y sobre `lms-shared-sw2` (`400`), sin abrir atajos en tabla `0` de `sw2`, sin duplicar nombres, rechazando decisiones inválidas, preservando `DENY` durante renovaciones de generación `1→0` y soportando failover de tránsito a `sw4`.
- **Prerrequisitos:** Topología D (`DPIDS`, `H1`, `H2`, `LMS`, `NOTAS`, `ADMINISTRACION`, `CONSOLA_DTI`).
- **Procedimiento:** Ejecutar `py -m unittest tests.test_r2_03_translate_policy -v`.
- **Resultado esperado:** `effective_table20_decision()` devuelve `Decision.DENY` en ida y retorno para solapamientos (incluyendo renovación `gen1 + gen0`); `0` reglas en tabla `0` de `sw2`; `0` reglas de tránsito para recursos denegados; `0` flujos para `consola_dti`; `ValueError` para `"ALLOW"`; `2` reglas en `sw4` y `0` en `sw1` en modo failover.
- **Resultado obtenido:** **PASS** (5/5 casos). Cobertura de `access.translate`: **98 %** (268 líneas).
- **Evidencias:** `resultados/unittest_matthew_r1_r2.txt`, `resultados/coverage_trace_r1_r2.txt`, `evidencias/registro_evidencia_comun.json`.
- **Comentarios u observaciones:** La validación contra OVS real (`ovs-ofctl dump-flows br-sdn` en `sw2`/`sw1`/`sw3`) se completa en la Fase B.
