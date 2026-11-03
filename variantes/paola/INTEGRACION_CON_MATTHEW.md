# Código recuperado de Paola para comparar con Matthew

Fuente: ocho respaldos privados VNRT verificados el 24/10/2026. PROCEDENCIA.json conserva nodo, ruta e identificadores de las capturas. No se hizo git add, commit, push ni despliegue en Matthew.

La carpeta reproduce rutas por nodo; no es un instalador. El servicio sdn-r1 de Paola ejecutaba `/opt/sdn-portal-paso4/vnrt_avz7_adapter.py`. La copia de DTI en `/opt/sdn-admin-paso7` es distinta y no debe elegirse solo por tener el mismo nombre. Revisar ExecStart/importaciones reales antes de modificar cualquier copia.

Comparar los cambios de renovación y coherencia de estado con la implementación actual de Matthew. Conservar su diseño R2 y adaptar la corrección, en lugar de reemplazar todo el adaptador. Los cambios de Paola esperan su propio generador de reglas y funciones de verificación, que pueden diferir del de Matthew.

No copiar las IP/MAC/DPID/ofport de `vnrt_flujos_https_paso3.py` como si fueran las de Matthew. No transferir secretos, base o certificados privados de Paola para que el programa simplemente arranque: usar la configuración e identidades de su slice y migrar solo los datos que se acuerden.

Al integrar: respaldar su versión, revisar diff, validar sintaxis, aplicar en ventana de prueba, reiniciar solo el servicio afectado y comprobar login, LMS/recursos por rol, renovación, logout, revocación selectiva, vencimiento y coherencia SQL/OVS. Un pull solo descarga archivos; no aplica estos pasos.

Estado: 55 Python con sintaxis revisada; no se detectaron valores secretos conocidos de las configuraciones privadas en los archivos exportados. Revisión limitada, no garantía frente a secretos desconocidos. Conservar ramas de trabajo y revisión humana antes de publicar.

Documentación detallada: `Proyecto/Respaldo_y_retorno_VNRT_20261024/` en el workspace original; se copiará a docs/paola en el repositorio siguiendo su guía 03.
