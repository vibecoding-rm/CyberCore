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

Esta demostración está implementada en `POST /v1/analysis/inventory`. Usa el
adaptador simulado, conserva la decisión y la evidencia en el flujo auditado, y
devuelve siempre `candidate`/`need_more_evidence` mientras falten producto y versión,
advisory autoritativo, comparación de rango y validación independiente.

### Estado de la Fase 4 — adaptador `run_nuclei_safe`

Implementado en `app/tools/nuclei.py` y `app/tools/nuclei_catalog.py`:

- **Allowlist humano con hash fijado** (`config/nuclei_templates.yaml`). El
  operador o el modelo sólo eligen IDs de ese allowlist; nunca rutas, etiquetas
  ni flags. `scripts/pin_nuclei_template.py` revisa una plantilla y añade su
  SHA-256. Si `nuclei -update-templates` la cambia, la ejecución se rechaza.
- **Sólo HTTP ligado al objetivo**: se rechazan plantillas `code`, `headless`,
  `javascript`, `file`, `flow`, `workflows` y `self-contained`.
- **Lo que se ejecuta es lo que se verificó**: los bytes con hash correcto se
  copian a un directorio temporal privado y Nuclei carga esa copia.
- **Flags fijos**: `-no-interactsh` (sin callbacks externos), `-disable-redirects`
  (una redirección podría salir del alcance), `-rate-limit 5`, `-concurrency 1`,
  `-retries 0`, sin actualizaciones. `-config config/nuclei-runtime.yaml` impide
  que la configuración del usuario añada proxy, cabeceras o `-code`.
- **Pasiva frente a activa**: cada plantilla declara `mode`; la evidencia
  registra `run_mode`, versión del motor y hash de cada plantilla.
- **Política**: `run_nuclei_safe` es `risk: high`, requiere aprobación y viene
  deshabilitada. Sólo acepta IP (sin DNS) dentro de `allowed_networks`.
- **No expuesto al orquestador LLM**: se invoca desde `/v1/tools/execute` con
  una aprobación de un solo uso.

Instalación en Windows: descarga `nuclei_*_windows_amd64.zip` desde
<https://github.com/projectdiscovery/nuclei/releases>, añade el `.exe` al PATH y
ejecuta `nuclei -update-templates` (queda en `~/nuclei-templates`).

### Validación y promoción a `confirmed`

`POST /v1/analysis/evidence` recibe sólo **IDs** de evidencia ya sellada por el
broker (`inventory_evidence_id` de `inspect_services` y
`validation_evidence_ids` de `run_nuclei_safe`). Cada evidencia se relee de
PostgreSQL y se recalcula su SHA-256; si no coincide se responde 409 y no se
analiza. El cliente no puede enviar cuerpos de evidencia.

La regla es determinista (`decide_status`), nunca la decide el modelo:

| Inventario | Rango de versión | Fuente con procedencia | Nuclei activo | Estado |
|---|---|---|---|---|
| simulado | cualquiera | cualquiera | cualquiera | `candidate` |
| real | afectado | sí | reproduce | **`confirmed`** |
| real | afectado | no | reproduce | `probable` |
| real | sin resolver | cualquiera | reproduce | `probable` |
| real | fuera de rango | cualquiera | reproduce | `candidate` (contradicción, revisión humana) |
| real | afectado | cualquiera | no | `probable` |
| real | resto | | no | `candidate` |

- Sólo cuenta una plantilla **activa**, ejecutada en real (no mock), contra la
  **misma IP**, con un hallazgo clasificado con **ese CVE**. Una detección pasiva
  es otro fingerprint, no una validación.
- Una ejecución activa sin resultado queda como "no reproducido"; nunca marca
  `false_positive`, porque una plantilla puede no cubrir la configuración.
- "Fuente con procedencia" = rangos NVD/OSV guardados con el hash de su registro
  original, o presencia en CISA KEV.

Nota: `evidence.append_only` está declarado en la política, pero PostgreSQL no lo
impone con triggers; la reverificación del hash al leer detecta modificaciones.
