# Pausar el proyecto y preparar Lab5

Requisitos: ocho respaldos descargados, integridad verificada, segunda copia privada y código exportado. No hace falta esperar al push para tener respaldo privado, pero sí comprobar ambas copias. Esta guía cambia el estado del laboratorio; ejecutarla solo al pasar de proyecto a Lab5.

No borrar bridges ni modificar ens3. El tráfico SSH y el OpenFlow de Lab5 usan la red de gestión. Estos pasos adaptan la Actividad 0 del previo a nuestra instalación con systemd.

## 1. Impedir que el proyecto vuelva a iniciar

El script de respaldo ya detuvo los servicios. Ahora deshabilitar el arranque automático para que no reaparezcan al reiniciar. En controller:

```bash
sudo systemctl disable --now sdn-portal sdn-admin sdn-r1 sdn-dhcp sdn-floodlight
systemctl is-active sdn-portal sdn-admin sdn-r1 sdn-dhcp sdn-floodlight
systemctl is-enabled sdn-portal sdn-admin sdn-r1 sdn-dhcp sdn-floodlight
```

Esperado: inactive y disabled. Los comandos is-active/is-enabled pueden devolver código distinto de cero precisamente porque están detenidos/deshabilitados. Si aparece active o enabled, revisar antes de seguir. Deshabilitar no impide un arranque manual o por dependencias; no volver a iniciar servicios sdn-* durante Lab5.

En h3:

```bash
sudo systemctl disable --now sdn-lms
```

En h4:

```bash
sudo systemctl disable --now sdn-notas sdn-recurso-administrativo
```

Si el inventario registra otros servicios del proyecto que invocan los mismos procesos, detenerlos también tras revisar sus definiciones. No desinstalar MySQL ni borrar sdn_g2 para hacer Lab5. Si falta RAM, se puede detener temporalmente `mysql` después del dump y con las aplicaciones detenidas; guardar su estado de arranque previo. No es obligatorio ni debe confundirse con borrar datos.

## 2. Desconectar y limpiar cada switch

Ejecutar en sw1, sw2 y sw3, cada uno en su propia terminal:

```bash
hostname
sw=$(hostname)
case "$sw" in sw1|sw2|sw3) ;; *) echo 'Nodo incorrecto'; exit 1;; esac
sudo ovs-vsctl del-controller "$sw"
sudo ovs-ofctl -O OpenFlow13 del-flows "$sw"
sudo ip neigh flush nud permanent dev "$sw"
sudo ovs-vsctl set bridge "$sw" protocols=OpenFlow13
sudo ovs-vsctl get-controller "$sw"
sudo ovs-ofctl -O OpenFlow13 dump-flows "$sw"
sudo ovs-vsctl show
```

Esperado: get-controller vacío, dump-flows sin entradas y show sin Controller. Las interfaces/puertos y el bridge permanecen. Si vuelven a aparecer reglas, identificar el proceso que las instala; no insistir con del-flows.

No ejecutar `ip neigh flush` en ens3 ni vaciar todas las rutas. La eliminación anterior se limita a vecinos permanentes del bridge nombrado, como indica el previo.

## 3. Mantener IP de h1/h2 sin el DHCP del proyecto

En el proyecto, h1 y h2 recibían su IP por DHCP de Kea. Si lo detenemos, sus concesiones pueden vencer y desaparecer; no conviene depender de una IP que todavía se vea unos minutos.

Primero copiar la herramienta desde Windows:

```powershell
Set-Location -LiteralPath 'D:\PUCP\CICLO 8\SDN\Proyecto\Respaldo_y_retorno_VNRT_20261024'
scp -P 5811 '.\scripts\datos_cliente_lab5.py' 'ubuntu@203.0.113.10:/home/ubuntu/datos_cliente_lab5.py'
scp -P 5812 '.\scripts\datos_cliente_lab5.py' 'ubuntu@203.0.113.10:/home/ubuntu/datos_cliente_lab5.py'
```

En h1 y después en h2:

```bash
hostname
sudo python3 ~/datos_cliente_lab5.py --lab-static
ip -br address show ens3
ip -br address show ens4
ip route
```

Esperado: h1 ens4=192.0.2.1/24, h2 ens4=192.0.2.2/24; ens3 y su ruta de gestión sin cambios. El script exige Ubuntu/networkd y un único YAML simple con ens4 DHCP, conserva el archivo original y solo reconfigura ens4. Si no coincide, se detiene: revisar configuración real. Guardar la ruta `RESPALDO PARA VOLVER A DHCP` para cada nodo y descargar privadamente esa carpeta antes de un eventual reset de discos.

En h3 verificar `ip -br address show ens4`: debe conservar 192.0.2.3/24 estática. h4 debe conservar 192.0.2.4/24. No necesitan estar activos los servidores HTTPS del proyecto para los pings de Lab5.

## 4. Comprobar puertos, procesos y espacio

En controller:

```bash
sudo ss -lntp | grep -E ':(6653|8080|8181|8101|443|8443) ' || true
pgrep -af 'floodlight|vnrt_avz7|gunicorn|kea-dhcp4' || true
df -h /
```

6653 y 8181 deben estar libres antes de ONOS; ningún proceso del proyecto debería seguir activo. Si una búsqueda muestra su propio comando, no confundirlo con un servicio. MySQL puede seguir en 127.0.0.1:3306. No ejecutar solo pkill: un servicio con Restart puede volver a arrancar.

**El previo exige al menos 1,5 GB libres antes de Docker/ONOS.** La última campaña observó un disco muy ajustado; no se sabe cuánto queda hoy. Pausar libera puertos y algo de RAM, no espacio en disco.

Si falta espacio:

```bash
sudo du -xhd1 /opt /var /root /home/ubuntu 2>/dev/null
sudo apt-get clean
df -h /
```

Después de dos copias privadas verificadas, los archivos tar.gz del respaldo que aún quedan en las VM son candidatos a trasladar fuera del slice. Identificar sus nombres exactos y eliminarlos localmente solo después de comparar hashes con las copias externas. No usar comodines sobre /opt ni /var/lib.

Otros candidatos requieren revisión concreta: el Floodlight antiguo bajo /root y los binarios del proyecto bajo /opt/sdn-floodlight. No se da aquí un borrado masivo automático: confirmar tamaños y archivo exacto preservado. Si hay que retirar binarios, la restauración usa la guía 05, sección de recuperación de archivos. Conservar MySQL y configuración si caben. Si no se alcanzan 1,5 GB, resolver almacenamiento/snapshot con VNRT antes de descargar ONOS; no continuar esperando que Docker quepa.

## 5. Continuar con el previo

Con los switches vacíos, servicios detenidos/deshabilitados, IP de h1/h2 estática y espacio suficiente, seguir las Actividades 1–5 del DOCX. En Actividad 0, la limpieza de procesos Floodlight ya está resuelta por systemd; borrar solo `/root/floodlight-1.2` no elimina nuestra instalación `/opt/sdn-floodlight`.

El proyecto usaba Java 8 para Floodlight. ONOS se ejecutará dentro de Docker; no cambiar globalmente Java del host para instalar ONOS sin necesidad. El instalador histórico del proyecto exige Java 8.

Al terminar el previo ejecutar el `slice_reset.yml` pedido por la Actividad 5 y conservar la imagen ONOS. **No reactivar el proyecto antes de la experiencia de Lab5**, porque el último inciso exige dejar los switches sin controlador/reglas. Volver al proyecto cuando termine esa experiencia o cuando el docente autorice cambiar el estado del slice.

No ejecutar simultáneamente el adaptador/Floodlight del proyecto y el control de ONOS sobre los mismos bridges.
