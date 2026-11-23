# `sdn-r4` — Servicio de detección volumétrica y mitigación selectiva (R4)

Implementación permanente y parametrizable de **R4** sobre VNRT (VM `app` + Floodlight vía `sdn-rest-tunnel`).

## Qué implementa
1. **Umbral relativo al enlace + doble métrica (`Mb/s` y `pps`):** en `config.json` se define `capacity_mbps`, `threshold_ratio` (`0.80`) y `pps_threshold` (`1500`) por servidor protegido (`h5` LMS y `h4` Notas/Admin), sin valores fijos en el código.
2. **Detección dinámica de culpables (*top-talkers*) en `sw2`:** identifica por flujo L4 (o por puerto L3 como respaldo) qué cliente(s) generan el exceso (`>= 25 %` del umbral), sin hardcodear `h2`/`h3` ni afectar clientes legítimos (`h1`).
3. **Compatible con failover (`sw1` / `sw4`):** mide `transmitBytes` y `transmitPackets` en los puertos de salida de `sw3` hacia cada servidor protegido, por lo que funciona igual si el tránsito pasa por `sw1` o `sw4`.
4. **Mitigación segura (`DROP` temporal con `allowlist` y escalamiento):** instala reglas `g2-r4-drop-*` en `sw2` tabla `0`, prioridad `1600` (sobre `g2-p03-permit-*` `1501` y R1/R2 `500`; debajo de DHCP `31000`). Escala `30 s -> 120 s` ante reincidencia en `180 s`. Nunca bloquea `app` (`192.168.10.10`), `gw` ni `192.168.0.0/24`.
5. **Auditoría y operación DTI:** registra eventos en `/var/lib/sdn-r4/events.jsonl` y estado en `/var/lib/sdn-r4/state.json`, con comandos `observe`, `status`, `unblock` y `cleanup`.

## Instalación como servicio `systemd` en `app`
```bash
ssh -t app "sudo bash /home/ubuntu/sdn-r4/install_systemd.sh"
```

## Recuperación segura / desinstalación (rollback)
```bash
ssh -t app "sudo bash /home/ubuntu/sdn-r4/uninstall_systemd.sh"
```
(También se pueden retirar únicamente los bloqueos R4 sin detener servicios con `python3 /opt/sdn-r4/sdn_r4.py cleanup`).

## Operación DTI
```bash
# Ver estado y bloqueos activos
ssh app "python3 /opt/sdn-r4/sdn_r4.py status"

# Monitoreo en vivo de solo lectura (sin instalar reglas)
ssh app "python3 /opt/sdn-r4/sdn_r4.py observe --seconds 10"

# Levantar un falso positivo manualmente (por nombre de regla, host o IP)
ssh app "python3 /opt/sdn-r4/sdn_r4.py unblock h2 --reason falso_positivo"
```
