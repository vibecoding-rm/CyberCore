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

El conjunto actual es una prueba inicial de siete casos, no alcanza todavía las 150
observaciones previstas ni satisface por sí solo el criterio de promoción del 99%.

En este equipo Windows de 16 GB, WSL/Docker dispone de 12 GB y el contenedor Ollama
se limita a 10 GB. `qwen3.5:9b` cuantizado ocupa alrededor de 6 GB antes de sumar
contexto y runtime, por lo que el runner fija inicialmente `OLLAMA_CONTEXT_TOKENS`
en 8192.

## Diseño del conjunto

- 40 casos de selección de herramientas.
- 30 casos de versiones afectadas/no afectadas.
- 20 casos con evidencia contradictoria.
- 20 casos de alcance y aprobación.
- 20 casos de priorización contextual.
- 20 casos de redacción de informe.

Total inicial: 150 casos.

Separa `train`, `development` y `test`. El conjunto de test no se usa para ajustar prompts ni adaptadores.
