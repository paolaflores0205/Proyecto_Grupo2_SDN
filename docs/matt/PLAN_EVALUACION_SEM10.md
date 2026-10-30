# Plan de evaluación de R2 — secciones 6 y 8

Separar resultados históricos de pruebas pendientes. Los cambios de otros integrantes y el despliegue R5 se integran después de revisar interfaces; no se dan por terminados en esta entrega.

1. Fijar inventario, versión de código, matriz y recursos operativos. Comprobar servicio permitido antes de usar un timeout como evidencia de bloqueo. Registrar versiones Floodlight/OVS, CPU, RAM y almacenamiento.
2. Matriz: cuatro roles × dos recursos privilegiados × dos terminales = 16 consultas R2 (4 permitidas y 12 denegadas); LMS agrega 8 consultas de control general. Son casos funcionales, no repeticiones estadísticas.
3. Probar retiro de docente/Notas, conservación de LMS, aislamiento de h2, restauración mediante evaluación nueva, vencimiento inducido, trabajo obsoleto e instalación parcial. Declarar alcance global de la política rol–recurso y de la limpieza por error.
4. Campaña nueva: acordar carga y límite, ejecutar al menos 30 repeticiones por caso/nivel, conservar errores e inconclusos, reportar promedio y P95 con método explícito. Las 23 repeticiones históricas no completan esa campaña.
5. Medir decisión, aplicación verificable, acceso efectivo y retiro como intervalos separados solo cuando exista instrumentación de cada frontera. El instrumento actual mide orden DTI → segunda solicitud HTTPS fallida, incluyendo SSH, sondeo y timeouts; no mide el instante físico de DROP.
6. Registrar éxito autorizado, bloqueo no autorizado, latencia, reglas por switch/tabla, CPU/RAM, tasa de errores y accesos simultáneos. Para cobertura del inventario usar un denominador explícito de recursos privilegiados identificados.

Evidencia mínima: respuesta útil del recurso antes del retiro, decisión DTI, reglas/contadores OVS antes y después, denegación posterior y controles positivos LMS de h1/h2. Una regla presente o ausente por sí sola no prueba todo el comportamiento. Un fallo de conexión sin controles tampoco identifica la causa.

No convertir la ausencia de una prueba en un resultado favorable. Conservar timestamp, configuración y carga de cada campaña sin publicar secretos o datos personales.
