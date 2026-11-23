# Validación en vivo de `sdn-r4.service` sobre VNRT (19/11/2026)

- **Servicio:** `sdn-r4.service` en VM `app` (`192.168.0.20`), PID `121678`, consumo observado `~13,0 MB` RAM.
- **Configuración activa:** `/etc/sdn-r4/config.json` (`capacity_mbps = 20.0`, `threshold_ratio = 0.80` → `16,0 Mb/s`, `pps_threshold = 1500 pps`, `consecutive_windows = 3`, `drop_priority = 1600` en `sw2` tabla `0`, `base_timeout_s = 30`, `escalated_timeout_s = 120`, `recidivism_window_s = 180`).
- **Bitácora fuente en VNRT:** `/var/lib/sdn-r4/events.jsonl`.

## Resultados de las 5 pruebas en vivo

| # | Prueba ejecutada | Resultado observado | Veredicto |
|---|---|---|---|
| **1** | Carga legítima sostenida bajo umbral (`h2` `6 Mb/s` + `h3` `6 Mb/s` = `12 Mb/s`, `6 s`) | `0` detecciones, `0` bloqueos `g2-r4-drop-*` | **PASS** |
| **2** | Ráfaga corta sobre umbral (`h2` `10 Mb/s` + `h3` `10 Mb/s` = `20 Mb/s`, solo `2 s`) | `0` falsos positivos, `0` bloqueos `g2-r4-drop-*` | **PASS** |
| **3** | Sobrecarga sostenida (`h2` `12 Mb/s` UDP/5201 + `h3` `12 Mb/s` UDP/5202 = `24,81 Mb/s`, `2497,5 pps`) con `h1` enviando tráfico legítimo (`5203`) | `00:04:35Z`: `detect` (`reason: mbps+pps`) en `h5`; identificó dinámicamente solo a `h2` (`12,40 Mb/s`) y `h3` (`12,40 Mb/s`) sin tocar `h1`; instaló y verificó en OVS `g2-r4-drop-h2-h5-udp5201` en **`83,4 ms`** y `g2-r4-drop-h3-h5-udp5202` en **`75,6 ms`** (`timeout_s: 30`) | **PASS** |
| **4** | Expiración automática de `30 s` + flood de paquetes pequeños por `pps` (`h2` → `h5:5201`, UDP `64 B`, `1,20 Mb/s` / `2341 pps`, muy debajo de `16 Mb/s`) | `00:05:05Z`: expiración exacta a los `30 s` de `h2` y `h3`. `00:07:01Z`: `detect` con **`reason: "pps"`** (`1,99 Mb/s`, `2341,3 pps`) → **`escalate`** automático a **`timeout_s: 120 s`** por reincidencia de `h2`, verificado en OVS en **`40,9 ms`** (`16 405` paquetes enviados, solo `7 925` recibidos antes del corte; resto descartado) | **PASS** |
| **5** | Desbloqueo manual DTI (`sdn_r4.py unblock h2 --reason prueba_dti`) | `00:07:13Z`: retiró inmediatamente `g2-r4-drop-h2-h5-udp5201` de Floodlight y registró `manual_unblock` en `/var/lib/sdn-r4/events.jsonl` | **PASS** |

## Limpieza verificada al cierre
- `iperf3` en `h5`: detenido (`0` procesos activos).
- Reglas temporales `g2-r4-testpermit-*` y `g2-r4-drop-*`: retiradas (`0` reglas residuales).
- `sw3` (`ens7`): cola estándar `pfifo_fast` sin alteraciones.
- Servicios activos: `sdn-r4.service` (`active`) y `sdn-r1.service` (`active`).
