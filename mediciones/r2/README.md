# Medición de retiro de permisos

`medir.py` se ejecuta desde la máquina de administración y usa workers SSH persistentes en controller, h1 y h2. Requiere la configuración y credenciales privadas descritas en `../../pruebas/r2/README.md`. No instala módulos del proyecto.

```bash
python mediciones/r2/resumir.py
python mediciones/r2/medir.py --ejecutar --trials 30
```

El primer comando solo resume el CSV histórico. El segundo sí cambia políticas: necesita cero sesiones iniciales, crea docente en h1 y estudiante en h2, comprueba LMS/Notas útiles y las reglas de Notas antes de retirar el permiso rol docente–Notas mediante la consola DTI real. Restaura esa política y cierra las sesiones en la limpieza. No ejecutar simultáneamente con las otras pruebas.

La política es global al rol/recurso; no se presenta como revocación exclusiva de una sesión. `t0` se toma antes de enviar el POST DTI desde el orquestador; `t1` al terminar la segunda consulta HTTPS nueva consecutiva fallida a Notas. Timeout por consulta 350 ms, intervalo 100 ms, deadline del instrumento histórico 15 s. También se verifican reglas retiradas y LMS útil en ambos terminales después del retiro. Esos controles son puntuales, no una demostración de disponibilidad continua.

## Datos históricos del 22 de octubre

24 ensayos iniciados: 23 completos y uno inconcluso al consultar OVS. Piloto excluido; la continuación falló antes de iniciar una nueva medición. No imputar tiempos al ensayo incompleto ni anunciar 30 repeticiones realizadas.

| Métrica observada (23 completos) | Promedio | P95 exploratorio nearest-rank |
|---|---:|---:|
| Respuesta DTI, incluido transporte SSH | 382.26 ms | 534.74 ms |
| Orden DTI → confirmación de denegación | 985.73 ms | 1024.51 ms |

Estos tiempos incluyen comunicación, sondeo y detección por timeout; no son latencia pura de OpenFlow, instante físico de descarte, capacidad máxima, concurrencia ni TCAM. Una campaña nueva debe reportar su propio denominador y errores. El CSV preserva el ensayo inconcluso y `resumir.py` no modifica los datos de entrada.

Las rutas y direcciones del instrumento se adaptaron a configuración para distribuirlo. La ejecución remota de esa adaptación queda pendiente; la validación local no sustituye la campaña del destino. Los nuevos registros se guardan en `VNRT_TEST_OUTPUT/mediciones.json`, fuera del histórico publicado.
