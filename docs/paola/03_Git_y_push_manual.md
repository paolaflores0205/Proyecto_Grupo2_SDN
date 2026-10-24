# Guardar código y documentación en Git sin subir secretos

Paola pidió hacer el push personalmente. Los comandos siguientes son instrucciones; no se ejecutaron. Git guarda versiones de archivos; no conserva servicios en ejecución, paquetes instalados ni una base MySQL por sí solo.

## 1. Clonar el repositorio del proyecto en una carpeta separada

**Ya realizado por Paola:** el repositorio se clonó en `D:\PUCP\CICLO 8\SDN\Proyecto\Codigo\Proyecto_Grupo2_SDN`. No volver a clonar si se continúa desde ese estado. La revisión encontró main limpio en d233878 (Código_Parcial_14_10), con paquete portable de tabla única del 10/10 y sin captura viva. Las mejoras multitabla y correcciones del 20–22/10 todavía no están integradas en esa rama.

En PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path 'D:\PUCP\CICLO 8\SDN\Proyecto\Codigo' | Out-Null
Set-Location -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Codigo'
git clone https://github.com/paolaflores0205/Proyecto_Grupo2_SDN.git
if ($LASTEXITCODE -ne 0) { throw 'Falló clone; no continuar con git add.' }
Set-Location -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Codigo\Proyecto_Grupo2_SDN'
git remote -v
git status --short
git branch --show-current
git log -5 --oneline
```

Si la carpeta ya existe, no repetir clone ni sobrescribirla: comprobar allí remote/status y conservar cualquier cambio. Si Git dice que el repositorio está vacío, no hay log todavía; es normal. Si requiere acceso, autenticar con Git Credential Manager o el mecanismo que ya uses, sin poner tokens en el comando ni en el remoto.

No hacer `git init` en toda la carpeta SDN ni usar el repositorio de Lab4. No usar `git push --force`.

Crear una rama nueva desde el estado recién clonado:

```powershell
git switch -c respaldo-paola-vnrt-20261024
```

Si ya existe, no recrearla: revisar la rama existente. Si clonas un repositorio vacío, Git permite crear la rama antes del primer commit.

## 2. Excluir datos privados antes de añadir archivos

Abrir `.gitignore` sin reemplazar reglas que ya tenga el grupo y añadir:

```gitignore
# Respaldos y estado privado del VNRT
Respaldos_privados_VNRT/
**/Respaldos_privados_VNRT/
*.tar.gz
*.tar.gz.sha256
*.partial
**/config.json
**/private/
**/usuarios-prueba.json
**/credenciales-dti.json
**/*.key
**/*.pem
**/.env
**/.env.*
**/sdn_g2.sql
**/mysql-app-users.sql
**/__pycache__/
*.pyc
```

Estas reglas son una segunda barrera. No detectan secretos incrustados y no eliminan archivos ya versionados. Los respaldos privados se guardan fuera de este repositorio.

## 3. Copiar estas guías y exportar el código real

Desde la raíz del repositorio clonado:

```powershell
New-Item -ItemType Directory -Force -Path '.\docs\paola' | Out-Null
Copy-Item -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldo_y_retorno_VNRT_20261024' -Destination '.\docs\paola\Respaldo_y_retorno_VNRT_20261024' -Recurse
```

Si la carpeta de destino ya existe, detenerse y comparar: este comando se plantea para una carpeta nueva, no para fusionar a ciegas. Exportar después de conseguir los ocho respaldos privados verificados:

```powershell
& 'C:\Users\Usuario\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldo_y_retorno_VNRT_20261024\scripts\exportar_codigo.py' --backups 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldos_privados_VNRT\campana_20261024' --out '.\vnrt\paola\captura_20261024'
if ($LASTEXITCODE -ne 0) { throw 'Falló exportación; no continuar con commit.' }
```

La salida conserva estructura por nodo y ruta de origen. Solo admite código .py/.html/.css/.inc de rutas concretas; excluye por diseño secretos y SQL. No exporta un instalador completo. Revisar los archivos porque un programa antiguo podría tener una clave escrita dentro.

No usar como única fuente `generated-hld-vnrt-v4`: es una base histórica y no contiene necesariamente los ajustes vivos de logs, renovación y estado. Tampoco basta subir el último adaptador aislado.

## 4. Copiar mediciones sin mezclar evidencia privada

```powershell
New-Item -ItemType Directory -Force -Path '.\evidencias\paola' | Out-Null
Copy-Item -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Mediciones_R1_G2\evidencias_20261020_h1' -Destination '.\evidencias\paola\evidencias_20261020_h1' -Recurse
Copy-Item -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Mediciones_R1_G2\evidencias_continuidad_20261020' -Destination '.\evidencias\paola\evidencias_continuidad_20261020' -Recurse
Copy-Item -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Mediciones_R1_G2\evidencias_retiro_logout_20261022' -Destination '.\evidencias\paola\evidencias_retiro_logout_20261022' -Recurse
Copy-Item -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Mediciones_R1_G2\evidencias_concurrencia_20261022' -Destination '.\evidencias\paola\evidencias_concurrencia_20261022' -Recurse
```

Revisar antes de publicar. Los JSON de medición fueron diseñados sin contraseñas/cookies, pero no asumir que cualquier archivo nuevo tiene esa propiedad. Un trial_id de medición no es el token de sesión. Capturas, DOCX y PPT pueden añadirse después de comprobar que no revelan secretos; no son necesarios para restaurar el runtime.

## 5. Revisar, commit y push manual

Primero mirar cambios sin preparar nada:

```powershell
git status --short
git diff -- .gitignore
```

Leer el código y comprobar que no hay claves privadas, contraseñas reales, cookies, tokens, dump SQL ni config.json. No publicar la salida de una búsqueda que encuentre secretos. Las referencias a `db_password` o `token_hash` en código no son por sí mismas secretos; sus valores reales sí.

Solo después preparar las rutas indicadas:

```powershell
git add -- .gitignore docs/paola/Respaldo_y_retorno_VNRT_20261024 vnrt/paola/captura_20261024 evidencias/paola
git diff --cached --stat
git diff --cached --name-only
git diff --cached --check
```

No usar `git add .` para evitar incluir archivos ajenos. Si se preparó un archivo incorrecto: `git restore --staged -- RUTA_DEL_ARCHIVO`, que lo saca del commit sin borrar la copia local. Si un secreto ya se publicó, retirarlo del último commit no basta: hay que rotarlo y revisar el historial.

Cuando el contenido sea correcto:

```powershell
git commit -m "Documenta y respalda avance VNRT R1 R2 de Paola"
git push -u origin respaldo-paola-vnrt-20261024
```

Este push crea/publica una rama de trabajo; no reemplaza el trabajo del grupo en la rama principal. Después revisar en GitHub y proponer integración. Si el push es rechazado, no forzarlo: revisar la causa. Para comprobar después:

```powershell
git status --short
git log -1 --oneline
git ls-remote --heads origin respaldo-paola-vnrt-20261024
```

El hash remoto debe coincidir con el commit local. **GitHub no sustituye el respaldo privado de los ocho nodos.**
