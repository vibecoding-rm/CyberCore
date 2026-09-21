# Guía maestra de construcción

## 1. Objetivo real

CyberCore no debe ser “una IA que hackea”. Debe ser un analista defensivo local que:

1. Recibe una intención del operador.
2. Comprueba alcance y autorización.
3. Selecciona una herramienta con contrato explícito.
4. Ejecuta mediante un adaptador aislado.
5. conserva salida original, hash, hora, objetivo y procedencia.
6. Correlaciona el resultado con fuentes actuales.
7. Pide evidencia adicional cuando no puede confirmar algo.
8. Genera un hallazgo trazable y una recomendación.

La evidencia decide; el modelo explica y organiza.

## 2. Separación de responsabilidades

### Orquestador

Candidato inicial: Qwen 3.5 9B cuantizado. Su trabajo es entender la solicitud, escoger herramientas y construir JSON válido. No decide por sí solo que existe una vulnerabilidad.

### Analista especializado

Candidato inicial: Foundation-Sec-8B-Reasoning cuantizado. Recibe evidencia ya recolectada, advisories y contexto del activo. En el MVP es sólo de análisis: no tiene permisos para ejecutar herramientas.

### Especialista de código

VulnLLM-R puede evaluarse posteriormente para revisión de repositorios. No forma parte del MVP de red.

### Tool Broker

Es el único componente capaz de invocar adaptadores. Valida:

- Herramienta registrada.
- Objetivo dentro del alcance.
- Riesgo.
- Aprobación.
- Presupuesto de ejecución.
- Tipos y límites de argumentos.

Nunca expone una shell general al modelo.

### Knowledge Service

Combina tres métodos:

- PostgreSQL para identificadores exactos, activos, servicios, versiones, CVE y estados.
- Búsqueda de texto completo para términos y fragmentos exactos.
- pgvector para similitud semántica en advisories, notas y remediaciones.

No uses embeddings para buscar un identificador exacto como `CVE-2026-12345`.

## 3. Flujo de un hallazgo

```text
Inventario -> candidato CVE -> advisory de proveedor -> versión afectada
          -> KEV/EPSS/CVSS -> exposición del activo -> validación independiente
          -> confianza -> remediación -> seguimiento
```

Estados recomendados:

- `candidate`: correlación inicial, sin confirmación suficiente.
- `probable`: versión y producto coinciden, falta validación independiente.
- `confirmed`: existe evidencia reproducible y fuente autoritativa.
- `false_positive`: la evidencia demuestra que no aplica.
- `accepted_risk`: aceptado formalmente, con responsable y vencimiento.
- `remediated`: corregido.
- `verified`: corrección confirmada por una nueva comprobación.

## 4. Qué construir primero

### Fase 0 — Seguridad y laboratorio

- Definir propietario del sistema.
- Crear inventario de activos de laboratorio.
- Especificar redes permitidas y denegadas.
- Mantener `TOOL_MODE=mock`.
- Ejecutar todas las pruebas.

Criterio de salida: toda IP pública debe ser bloqueada y ninguna acción de riesgo puede ejecutarse sin aprobación.

### Fase 1 — Modelos sin herramientas

- Instalar Ollama o llama.cpp.
- Probar cada modelo por separado.
- Medir RAM, tokens/s, latencia, JSON válido, español y seguimiento de instrucciones.
- No cargar dos modelos grandes simultáneamente en 16 GB.

Criterio de salida: el modelo orquestador produce llamadas estructuradas fiables; el especialista distingue evidencia suficiente de insuficiente.

### Fase 2 — Descubrimiento seguro

- Crear adaptador Nmap sólo con opciones fijas.
- Prohibir argumentos crudos aportados por el modelo.
- Limitar tamaño de CIDR, duración y concurrencia.
- Guardar XML/JSON original y su hash.

Criterio de salida: descubrimiento reproducible en laboratorio, sin salida de alcance.

### Fase 3 — Inteligencia de vulnerabilidades

- Ingerir CISA KEV, EPSS, OSV y NVD.
- Añadir advisories de proveedor cuando existan.
- Resolver producto, versión y rangos afectados.
- Marcar fecha de actualización y procedencia de cada dato.

Criterio de salida: consultas exactas y auditables, sin inventar CVE.

### Fase 4 — Validación

- Añadir Nuclei con lista de etiquetas/plantillas permitidas.
- Ejecutar sólo con aprobación.
- Separar pruebas pasivas de activas.
- Registrar versión del template y hash.

Criterio de salida: ningún hallazgo pasa a `confirmed` sin evidencia suficiente.

### Fase 5 — Endpoints y gestión

- Wazuh mediante API para inventario.
- Greenbone mediante `python-gvm` para tareas existentes.
- DefectDojo para deduplicación y ciclo de vida.

### Fase 6 — Entrenamiento

Sólo después de disponer de buenas trazas:

- Construir pares entrada/salida con decisiones correctas.
- Eliminar secretos y datos personales.
- Reservar un conjunto de evaluación sin contaminar.
- Entrenar comportamiento con QLoRA en Colab.
- Mantener CVE, versiones y feeds fuera de los pesos.

## 5. Hardware de 16 GB

Configuración prudente:

- Un modelo cargado a la vez.
- Contexto inicial de 8K–16K, no 64K por costumbre.
- PostgreSQL ligero.
- Sin Neo4j/Graphiti en el MVP.
- Wazuh/Greenbone preferiblemente en otros nodos o encendidos por fases.
- Swap configurado, pero no usado como sustituto de RAM para inferencia continua.

## 6. Primera meta práctica

La primera demostración útil no necesita autonomía total. Debe responder:

> “En este inventario simulado, ¿qué falta comprobar antes de afirmar que el activo es vulnerable?”

El sistema debe devolver una lista de evidencias faltantes y no inventar una conclusión.
