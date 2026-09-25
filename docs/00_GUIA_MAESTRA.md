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

El 9B actual es el baseline. El objetivo es un modelo base de 3–4B con un
adaptador exclusivo de orquestación. Escoge herramientas y construye JSON
válido, pero no decide que existe una vulnerabilidad.

### Analista especializado

Usa un segundo adaptador sobre el mismo modelo base ligero. Recibe evidencia,
advisories y contexto del activo; no ejecuta herramientas ni decide estados.
Foundation-Sec-8B-Reasoning queda como referencia, no como candidato inicial de
producción, por tamaño, idioma declarado y revisión de licencia pendiente.

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
- Entrenar comportamiento con LoRA eficiente en una GPU temporal.
- Mantener CVE, versiones y feeds fuera de los pesos.
- Entrenar orquestación y análisis en adaptadores distintos.
- Comparar primero Qwen3.5-4B y Ministral 3 3B con el 9B como control.

El contrato, dataset, gates y roadmap están en
`docs/08_MODELO_ANALISTA_LIGERO.md`.

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

`evidence` es de sólo inserción en PostgreSQL (migración 0006): los triggers
rechazan `UPDATE`, `DELETE` y `TRUNCATE`. Sólo un superusuario que desactive
triggers puede saltárselo, y aun así la reverificación del hash al leer lo detecta.

### Estado de la Fase 5 — `get_wazuh_inventory`

Adaptador de sólo lectura en `app/tools/wazuh.py` contra la API del servidor
Wazuh (`/security/user/authenticate`, `/agents`, `/syscollector/{id}/os`,
`/packages`, `/ports`):

- El modelo sólo aporta la IP del activo (validada por la política); la URL del
  manager y las credenciales vienen de `.env` (`WAZUH_API_*`) y nunca aparecen en
  la evidencia ni en los errores. Usa un usuario de Wazuh con rol de sólo lectura.
- TLS verificado por defecto; con certificado autofirmado, indica su CA en
  `WAZUH_CA_BUNDLE` en lugar de desactivar la verificación.
- Si ningún agente o varios agentes tienen esa IP, no se elige uno: la evidencia
  lo indica y no contiene paquetes. Los agentes se refiltran localmente por IP
  para no revelar otros hosts si el servidor ignorase el filtro.
- Paquetes paginados y limitados a 5000 (`packages_truncated`), SO y puertos en
  escucha con el proceso que los abre.
- Política: `risk: low`, sin aprobación, **deshabilitada** hasta configurar Wazuh.

Uso previsto: segunda fuente de versión. Nmap ve `OpenSSH 9.6p1` desde la red;
Wazuh ve el paquete `openssh-server 1:9.6p1-3ubuntu13.5`, cuya revisión de
distribución indica posibles backports.

### Greenbone (`python-gvm`, GMP)

- `start_greenbone_task` (`risk: high`, aprobación): sólo **inicia tareas ya
  configuradas** en gvmd, por UUID. Antes de iniciarla lee de gvmd los hosts
  reales del objetivo de la tarea y exige que **todos** estén dentro del
  `target` validado por la política y firmado en la aprobación. Así, editar la
  tarea en Greenbone para ampliar su alcance no burla la aprobación. Nombres DNS
  o rangos no verificables se rechazan. No inicia tareas ya en curso.
- `get_greenbone_results` (`risk: low`, sólo lectura): resultados con QoD ≥ 70 y
  overrides aplicados (host, puerto, NVT, severidad, CVE). Si el informe contiene
  hosts fuera del objetivo se rechaza sin nombrarlos.
- Conexión por socket Unix (`GREENBONE_SOCKET_PATH`) o TLS
  (`GREENBONE_HOST`/`PORT` + `GREENBONE_CAFILE`); credenciales sólo en `.env`.
  `python-gvm` parsea con `resolve_entities=False` (sin XXE).
- Ambas herramientas vienen deshabilitadas en `config/policy.yaml`.

### DefectDojo (exportación de hallazgos)

`POST /v1/findings/export` recibe los mismos IDs de evidencia sellada que
`/v1/analysis/evidence`, **rehace el análisis en el servidor** y envía el
resultado con `reimport-scan` (formato *Generic Findings Import*). El cliente
nunca envía el hallazgo ya construido.

- Sólo se exportan `probable` y `confirmed`; `verified=true` sólo en `confirmed`.
- Severidad por bandas CVSS v3; descripción con estado, observaciones, evidencia
  pendiente e IDs/SHA-256 de la evidencia sellada; CWE, vector CVSS, KEV y alias.
- `unique_id_from_tool = cybercore:<ip>:<cve>` y **un test por activo y CVE**:
  el reimport puede cerrar hallazgos ausentes del archivo, así que compartir un
  test entre exportaciones mitigaría hallazgos ajenos. También se envía
  `close_old_findings=false`.
- `dry_run: true` devuelve el hallazgo sin enviarlo (útil sin DefectDojo).
- Token en `DEFECTDOJO_API_TOKEN`; no aparece en respuestas ni errores.

Con esto la Fase 5 queda implementada. Queda la Fase 6 (entrenamiento QLoRA),
que requiere trazas reales acumuladas.
