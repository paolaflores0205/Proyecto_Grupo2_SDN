> Publicación saneada: IP/MAC/DPID son ficticios. El JAR y SHA256SUMS del ZIP original no se incluyen. Obtener vendor/floodlight.jar del paquete original autorizado antes de usar prepare.py. Consultar también el README raíz.

# Despliegue portable R1/R2 — Grupo 2

Este paquete reproduce la implementación final de autenticación, sesiones, autorización por rol, administración/auditoría y DHCP reservado. Incluye Floodlight, aplicación Python, MySQL, páginas de recursos y reglas de red. **No incluye R5, Suricata, cambios al gateway ni reglas antiguas de pruebas.**

No ejecutes los archivos históricos por sus nombres. Primero lee **GUIA_CODEX.md**. El punto de entrada es `prepare.py`, seguido de `install_node.py` dentro del directorio generado.

1. Inventariar las ocho VMs y confirmar los enlaces reales. Obtener IP, MAC, interfaces, DPID y puertos OVS.
2. Copiar `topology.example.json` a un archivo propio; sustituir los valores de ejemplo. Marcar `confirmed_after_inventory: true` solamente después de revisar la correspondencia completa.
3. Ejecutar en una computadora con Python 3.10 o superior: `python prepare.py topology.json --out generated-vnrt`. Esto genera archivos; NO se conecta ni modifica VMs.
4. Transferir `generated-vnrt` a cada VM por SCP/SFTP. Instalar primero sw1–sw3, luego h3/h4, controller y finalmente h1/h2, siguiendo la guía. Mantener disponible la consola VNRT.
5. Verificar servicios, reglas efectivas, acceso por rol y revocación. Las credenciales y certificados nuevos se generan en el VNRT de destino; no son los de Matthew.

La configuración admite direcciones, MAC, DPID, nombres de interfaces/bridges y puertos distintos. **Mantiene la topología lógica de tres switches, dos clientes y dos servidores**: no es un instalador general de campus ni de una topología arbitraria. Si hay más nodos/enlaces, otro usuario Linux, interfaces compartidas o una instalación previa, se necesita una adaptación revisada.

## Archivos principales

| Archivo/directorio | Uso |
|---|---|
| `GUIA_CODEX.md` | Instrucciones completas para el compañero y su Codex |
| `topology.example.json` | Única configuración de red de entrada; NO copiar sus valores sin inventario |
| `prepare.py` | Valida y genera código/configuración ajustados al destino |
| `install_node.py` | Instala una VM localmente, con confirmación de laboratorio limpio |
| `network_data.py` | Cambia exclusivamente la interfaz de datos, respaldando Netplan |
| `seed_database.py`, `schema.sql` | Base vacía, matriz de permisos y nuevas cuentas/secretos |
| `source/` | Portal, sesiones, adaptador R1/R2, administración, recursos y reglas |
| `smoke_test.py` | Prueba interactiva desde h1/h2; no guarda contraseñas ni cookies |
| `vendor/` | JAR de Floodlight usado en la implementación y avisos de licencias |
| `SHA256SUMS.json` | Integridad de todos los archivos distribuidos |
| `VALIDACION.md` | Alcance de las comprobaciones del paquete |

La versión original del proyecto fue probada en el VNRT de Matthew. El nuevo instalador portable requiere verificación en el entorno de destino: no se afirma que ya fue desplegado allí. Leer las restricciones y el procedimiento de recuperación antes de instalar.
