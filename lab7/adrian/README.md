# R3 y coherencia de reglas del Lab 7

La entrega de Adrián verifica el vínculo IP, MAC y puerto y la coherencia de reglas de `sw2`. Reutiliza `check_binding()` de R3 y usa el generador de R1/R2 para construir la referencia de las reglas permanentes. Las fuentes se leen en modo observación.

| Ruta | Contenido |
| --- | --- |
| `codigo/coherencia.py` | Comparador de capturas normalizadas y comprobación de precedencia de DROP selectivos. |
| `codigo/captura_vnrt.py` | Captura en vivo de las reglas permanentes de `sw2`, tablas 10, 20 y 30. |
| `codigo/test_binding.py` | Pruebas sobre la función de binding de R3. |
| `codigo/test_coherencia.py` | Pruebas de comparación y transiciones con datos sintéticos. |
| `casos.csv` | Fichas y trazabilidad de validación. |
| `diseno.md` | Texto técnico para el informe grupal. |

## Reproducir las pruebas

En PowerShell, desde la raíz de la copia de trabajo del grupo.

```powershell
$env:PYTHONPATH = (Resolve-Path '.\Avance12_Adrian').Path
py -B -m unittest discover -s '.\lab7\adrian\codigo' -v
```

En el nodo `app` de VNRT.

```bash
cd ~/lab7/adrian
PYTHONPATH=/opt/sdn-p03 python3 -B -m unittest discover -s codigo -v
python3 -B codigo/captura_vnrt.py
```

El verificador también procesa dos JSON normalizados con `python3 codigo/coherencia.py esperado.json observado.json`. La referencia incluye `revision`, `generations`, `rules` y, opcionalmente, `drop_checks` con los índices de los DROP selectivos. La observación incluye `complete`, `before` y `after` con revisión y generaciones, y `rules`. Ambas listas deben tener el mismo ámbito y las reglas potencialmente competidoras para cada DROP marcado. Cada regla lleva `dpid`, `table`, `priority`, `match`, `actions`, `idle_timeout` y `hard_timeout`. Usa campos explícitos para protocolo en los matches y una lista ordenada de acciones e instrucciones canónicas. Las acciones vacías representan DROP. El código de salida es 0 para coherencia, 1 para discrepancia y 2 para una transición o captura no verificable.

## Pasar el aporte a GitHub

Copia los archivos que quieras publicar a tu clon del repositorio. Puedes versionar `codigo/`, `README.md`, `diseno.md` y `casos.csv`. Para publicar los JSON de VNRT, usa copias saneadas de las evidencias.

```powershell
git status --short
git add -- lab7/adrian/codigo lab7/adrian/README.md lab7/adrian/diseno.md lab7/adrian/casos.csv
git diff --cached --stat
git commit -m "Agrega verificación de coherencia R3 para Lab 7"
git push -u origin HEAD
```

Ejecuta estos comandos desde el clon del repositorio del grupo y sobre tu rama. Las pruebas de binding requieren la función original de R3. En VNRT usan `/opt/sdn-p03`. En una copia local, apunta `PYTHONPATH` a la carpeta que contenga `r3.py`, `r5.py` y `floodlight.py`.
