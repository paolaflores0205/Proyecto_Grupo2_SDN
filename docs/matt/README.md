# R2 de Matt

Esta entrega añade la versión multitabla de autorización de recursos, pruebas funcionales y medición de retiro de permisos. Parte del commit base `d233878cecf2a310e9bd4c48a4c9cc835c0983a0`; conserva el despliegue portable del grupo. No incorpora la rama de Paola ni implementa R5.

| Carpeta | Contenido |
|---|---|
| `actualizacion-multitabla/` | Tres módulos, instalación de actualización y recuperación. Requiere el despliegue base generado para el inventario de destino. |
| `pruebas/r2/` | Matriz, sesiones independientes, retiro selectivo, trabajo obsoleto e instalación parcial; configuración SSH y direcciones de ejemplo. |
| `mediciones/r2/` | Instrumento DTI → denegación observable, estadística reproducible y CSV histórico sin credenciales. |
| `docs/matt/` | Diseño, dimensionamiento, resultados y plan de evaluación de las secciones a cargo de Matt. |

Orden de lectura: [diseño](R2_DISENO_Y_REGLAS.md), [guía de migración](../../actualizacion-multitabla/README.md), [pruebas](../../pruebas/r2/README.md), [mediciones](../../mediciones/r2/README.md) y [evaluación pendiente](PLAN_EVALUACION_SEM10.md).

Los tres módulos proceden de la migración funcional del 21 de octubre. Para esta distribución se exige `data_cidr` explícito y se adaptan rutas y direcciones de los instrumentos. La adaptación se comprobó localmente con análisis de sintaxis, cinco pruebas de catálogo y una de estadística. No se ejecutó nuevamente contra un VNRT ni se desplegó en el entorno de los compañeros.

No contiene usuarios o contraseñas de operación, cookies, claves privadas, dumps SQL, respaldos completos ni el JAR de Floodlight. Las cuentas y certificados públicos de confianza deben prepararse por un canal privado. La actualización conserva dependencias de R1, portal y administración del paquete base.
