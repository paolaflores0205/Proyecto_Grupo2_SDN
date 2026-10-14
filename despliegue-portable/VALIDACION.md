# Validación del paquete — 10/10/2026

## Comprobaciones offline realizadas

- Las 41 reglas base generadas con la configuración de referencia coinciden exactamente (match, acción, prioridad, tabla y tiempos) con el código de la implementación final, no con concesiones antiguas.
- Los seis casos cliente–recurso (h1/h2 × LMS/Notas/Administración) generan las mismas cuatro reglas individuales que el diseño final de referencia.
- Se generó otra configuración con subred de datos 203.0.113.0/24, gestión diferente, otras MAC y DPID, bridges/interfaces diferentes y ofports 4–12. Conserva 41 reglas base y cuatro por permiso; todos los matches y outputs usan los valores nuevos.
- No quedan IP originales de datos en el código, HTML ni properties generados para esa configuración alternativa.
- Se rechazan inventario no confirmado, IP/MAC/DPID duplicados, colisiones de puertos y la interfaz administrativa dentro de OVS.
- Los archivos Python de distribución y de ambas configuraciones generadas se analizaron sintácticamente sin errores.
- El SQL contiene diez estructuras de tablas, sin INSERT de datos del VNRT original ni contadores AUTO_INCREMENT heredados.
- Se revisó que no se distribuyan endpoint SSH original, rutas Windows personales, claves privadas PEM, certificados originales, config.json privados ni credenciales generadas.
- Se verificaron hashes del contenido distribuido e integridad CRC del ZIP final.

## Lo que esto NO prueba

El nuevo instalador portable **no se ejecutó en el VNRT de los compañeros**. No se afirma que APT, systemd, Netplan, Java, MySQL y Kea estén configurados igual en todas sus VMs. La equivalencia del catálogo no equivale a un despliegue integral validado en otro entorno.

La implementación original R1/R2 se probó funcionalmente en el VNRT de Matthew; el paquete conserva ese código y añade generación/configuración para destino e instalación limpia. Deben seguirse las verificaciones de GUIA_CODEX.md después de instalar. No incluye mediciones de carga del avance 8, TCAM física, pruebas del campus ni implementación R5.

No se aplicaron cambios de red ni de servicios al VNRT de Matthew para construir este paquete. La recuperación mediante consola y los respaldos deben prepararse antes de cualquier despliegue de destino.
