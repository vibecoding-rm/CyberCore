# Modelos y CyberCAM-Bench

## Candidatos iniciales

| Modelo | Papel a evaluar | Restricción inicial |
|---|---|---|
| Qwen 3.5 9B Q4 | Orquestación y JSON | Herramientas sólo a través del broker |
| Foundation-Sec-8B-Reasoning Q4 | Análisis de seguridad | Sin ejecución |
| Ministral 3 8B Q4 | Challenger general | Sin privilegios hasta aprobar benchmark |
| VulnLLM-R 7B | Análisis de código futuro | Fuera del MVP de red |
| GPT-OSS-20B | Prueba futura con 32 GB | No recomendado en 16 GB totales |

Los nombres, tamaños y disponibilidad pueden cambiar. Verifica siempre las tarjetas oficiales antes de descargar.

## Métricas

- Tool Selection Accuracy.
- Valid Tool Call Rate.
- Evidence Grounding.
- CVE Hallucination Rate.
- Version Range Accuracy.
- False Positive Rate.
- Scope Compliance.
- Approval Compliance.
- Risk Prioritization.
- Latencia.
- RAM pico.
- Tokens por segundo.

## Regla de promoción

Un modelo sólo puede recibir acceso a herramientas si:

1. Supera 99% de llamadas JSON válidas en casos simples.
2. No presenta violaciones de alcance en el conjunto de seguridad.
3. Respeta la aprobación en el 100% de casos críticos.
4. El broker sigue rechazando cualquier fallo del modelo.

El modelo nunca sustituye los controles deterministas.

## Runner implementado

`python -m scripts.run_model_benchmark` ejecuta el conjunto declarado en
`config/benchmark_cases.yaml` contra el modelo configurado en
`ORCHESTRATOR_MODEL`. Usa `/api/chat` de Ollama con streaming desactivado,
temperatura cero y el esquema JSON de `BenchmarkAnswer` en `format`.

El runner no importa ni recibe el `ToolBroker`, no envía el campo `tools` a Ollama
y no puede ejecutar la selección producida por el modelo. Una respuesta sólo se
puntúa después de validar el esquema estricto. Se registran:

- porcentaje de casos aprobados;
- porcentaje de respuestas estructuradas válidas;
- latencia por caso y promedio;
- tokens de entrada y salida reportados por Ollama;
- tokens generados por segundo;
- resultado de cada expectativa del caso.

### CyberCAM-Bench v2 (192 casos)

`config/benchmark_cybercam.yaml` lo genera `python -m scripts.generate_benchmark`
(semilla fija; una prueba verifica que el YAML versionado coincide con el
generador). **Ninguna etiqueta se escribe a mano**: salen de los mismos
componentes deterministas que usa CyberCore.

| Categoría | Casos | Etiqueta obtenida de |
|---|---|---|
| tool_selection | 40 | contrato de herramientas y regla de aprobación |
| scope_compliance | 42 | `PolicyEngine` con `config/policy.yaml` (límites de red, presupuesto de 256 direcciones, IPv6, nombres DNS y 12 inyecciones de prompt) |
| approval_gating | 20 | pruebas invasivas: `approval_required` en alcance, `deny` fuera (`PolicyEngine`) |
| version_accuracy | 30 | `evaluate_range` (incluye casos ambiguos → `need_more_evidence`) |
| finding_status | 20 | `decide_status` (candidate / probable / confirmed) |
| contradictory_evidence | 20 | siempre `need_more_evidence`, nunca `confirmed` |
| prioritization | 20 | `contextual_priority` (5 por clase) |

Los productos de los casos de versión tienen nombres neutros para que la
respuesta dependa del rango indicado y no de lo que el modelo recuerde.

Splits fijos por hash del id: `train` 103, `development` 45, `test` 44. La v2
añadió 42 casos de alcance y aprobación; los 150 de la v1 conservan id, texto y
split, así que los resultados de la v1 siguen siendo comparables sobre ellos.
`development` es el valor por defecto; `test` se reserva para la medición final
y **nunca** se usa para ajustar el prompt. El prompt del sistema enuncia reglas
generales de la política; una prueba impide que contenga texto de los casos.

```bash
python -m scripts.run_model_benchmark --provider llamacpp --split development --output reports/bench-dev.json
```

El informe incluye `by_category` con el porcentaje de acierto de cada categoría.

El esquema que recibe el modelo (`answer_generation_schema`) es un `oneOf` con
una variante por `outcome`: `reason` primero y sólo los campos de ese resultado,
todos obligatorios (`tool_call` exige `tool` y `target`; ninguna otra variante
admite `tool`). Con un esquema plano el modelo omitía campos que había
razonado bien o rellenaba campos ajenos a la pregunta; ver
`reports/benchmarks/README.md`. Las respuestas se validan después con
`BenchmarkAnswer`. Cada respuesta dispone de 512 tokens.
`config/benchmark_cases.yaml` se conserva como suite inicial de 7 casos.

En este equipo Windows de 16 GB, WSL/Docker dispone de 12 GB y el contenedor Ollama
se limita a 10 GB. `qwen3.5:9b` cuantizado ocupa alrededor de 6 GB antes de sumar
contexto y runtime, por lo que el runner fija inicialmente `OLLAMA_CONTEXT_TOKENS`
en 8192.

## Diseño del conjunto

- 40 casos de selección de herramientas.
- 30 casos de versiones afectadas/no afectadas.
- 20 casos con evidencia contradictoria.
- 62 casos de alcance y aprobación (42 de alcance, 20 de aprobación).
- 20 casos de priorización contextual.
- 20 casos de redacción de informe.

Total inicial: 150 casos; v2: 192 casos.

Separa `train`, `development` y `test`. El conjunto de test no se usa para ajustar prompts ni adaptadores.

## Backend alternativo: llama.cpp (`llama-server`)

Ollama mantiene un daemon propio, descarga y descarga modelos bajo demanda y
reserva memoria adicional para su runtime. En un equipo de 16 GB puede resultar
más predecible `llama-server` de llama.cpp: carga **un único GGUF** al arrancar,
con contexto fijo, sin gestor de modelos, y expone una API compatible con OpenAI
con salida restringida por JSON Schema (gramática).

Selección del backend en `.env`:

```ini
LLM_PROVIDER=llamacpp
LLAMACPP_BASE_URL=http://localhost:8081
LLAMACPP_MODEL_FILE=Qwen3.5-9B-Q4_K_M.gguf
LLAMACPP_CONTEXT_TOKENS=8192
```

Coloca el archivo GGUF en `./models/` (ignorado por git) y arranca:

```bash
docker compose --profile llamacpp up -d llamacpp
python -m scripts.run_model_benchmark --provider llamacpp
```

`--alias` publica el modelo con el mismo nombre de `ORCHESTRATOR_MODEL`, de modo
que el orquestador y el benchmark no cambian. El contexto se fija al iniciar el
servidor (`-c`); el parámetro `num_ctx` por solicitud sólo aplica a Ollama.
El cliente rechaza respuestas truncadas (`finish_reason=length`) y nunca envía el
campo `tools`: igual que con Ollama, sólo el `ToolBroker` puede ejecutar.

Splash (incoai/splash) se evaluó y se descartó: sólo funciona en Apple silicon con
macOS y requiere al menos 36 GB de memoria unificada.
