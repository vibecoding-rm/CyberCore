# Documentación de CyberCore

CyberCore es un analista defensivo local, orientado a evidencia, para redes y
equipos expresamente autorizados. Este índice separa lo que existe hoy de lo
que todavía está en investigación.

## Estado del producto

| Área | Estado | Fuente principal |
|---|---|---|
| Política, alcance, aprobaciones y auditoría | Implementado | [Controles](07_FASE_0_CONTROLES.md) |
| Broker y adaptadores defensivos | Implementado | [Arquitectura](01_ARQUITECTURA.md) |
| Evidencia, CVE, rangos y estados | Implementado | [Datos](03_DATOS_Y_CONOCIMIENTO.md) |
| Expediente portable firmado (Ed25519) | Implementado | [README](../README.md#-api-rest) |
| Filtro de alcance previo al modelo | Implementado, heurístico (la frontera es el broker) | [intent_guard](../app/core/intent_guard.py) |
| Orquestador local 9B | Baseline implementado | [Modelos](02_MODELOS_Y_BENCHMARK.md) |
| Modelo base ligero 3–4B | Qwen3.5-4B medido y no promovido (M0); Ministral 3 3B pendiente | [Analista ligero](08_MODELO_ANALISTA_LIGERO.md) |
| Adaptador LoRA del orquestador | Experimental, no promovido | [Entrenamiento](05_ENTRENAMIENTO_QLORA.md) |
| Contrato del analista, puerta automática y control sin modelo | Implementado | [Analyst-Bench](09_ANALYST_BENCH.md) |
| Analyst-Bench (casos, revisión con rúbrica) | Diseñado, sin casos | [Analyst-Bench](09_ANALYST_BENCH.md) |
| Adaptador LoRA del analista | Planificado | [Analista ligero](08_MODELO_ANALISTA_LIGERO.md) |

“Planificado” no debe presentarse en README, releases o demos como una
capacidad terminada.

## Orden de lectura

1. [Guía maestra](00_GUIA_MAESTRA.md): objetivo y fases.
2. [Arquitectura](01_ARQUITECTURA.md): límites entre modelo, broker y motores.
3. [Modelo analista ligero](08_MODELO_ANALISTA_LIGERO.md): dirección actual.
4. [Modelos y CyberCAM-Bench](02_MODELOS_Y_BENCHMARK.md): selección y gates.
5. [Analyst-Bench](09_ANALYST_BENCH.md): cómo se decide si hace falta un analista LLM.
6. [Entrenamiento LoRA](05_ENTRENAMIENTO_QLORA.md): pipeline reproducible.
7. [Seguridad y operación](04_SEGURIDAD_Y_OPERACION.md): controles operativos.
8. [Datos y conocimiento](03_DATOS_Y_CONOCIMIENTO.md): fuentes y persistencia.

## Fuentes de verdad

- Contratos ejecutables: código y esquemas Pydantic.
- Controles de seguridad: `config/policy.yaml`, `ToolBroker` y pruebas.
- Resultados de modelos: JSON bajo `reports/benchmarks/`, nunca sólo texto.
- Dataset: manifiesto, hashes y auditoría de la versión usada.
- Dirección de producto: [modelo analista ligero](08_MODELO_ANALISTA_LIGERO.md).

Si una descripción contradice el código o un reporte versionado, se corrige la
descripción; no se rebaja el control para hacerla coincidir.
