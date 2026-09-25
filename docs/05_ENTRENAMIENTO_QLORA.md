# Entrenamiento posterior con LoRA especializado

## Cuándo hacerlo

No entrenes antes de que el sistema funcione con prompts, herramientas y evaluación. Primero necesitas ejemplos correctos producidos o revisados por humanos.

## Qué aprenderá el adaptador del orquestador

- Elegir una herramienta registrada cuando corresponda.
- Construir el JSON exacto del contrato de producción.
- Abstenerse cuando no necesita una herramienta.
- Respetar el lenguaje de aprobación y alcance que las guardas hacen cumplir.

El futuro adaptador **analyst** interpreta evidencia y redacta recomendaciones
con otro esquema, dataset y benchmark. Ambos pueden compartir un modelo base,
pero nunca pesos LoRA ni ejemplos de protocolos distintos. Véase
`docs/08_MODELO_ANALISTA_LIGERO.md`.

## Qué no aprenderá ningún adaptador

- Listas de CVE actuales.
- Valores EPSS.
- Catálogo KEV.
- Versiones actuales de productos.
- Secretos, IP internas reales o datos personales.

## Trazas del orquestador (paso 1 del pipeline)

Cada `POST /v1/orchestrator/run` se graba en PostgreSQL (migración
`0007_agent_traces`), en tablas de sólo inserción:

- `agent_runs`: intención del operador, quién la lanzó, modelo, estado, informe
  final y esquema de respuesta exigido al modelo.
- `agent_steps`: por cada llamada al modelo, los **mensajes exactos** enviados,
  la **salida cruda** (aunque no sea JSON válido), el error si lo hubo, la
  observación devuelta y `execution_id`, que enlaza con la fila auditada de
  `executions` cuando el paso llamó a una herramienta.
- `agent_trace_reviews`: revisiones humanas; la más reciente manda.

Revisión (rol `approver`; nadie revisa sus propias ejecuciones):

```text
GET  /v1/traces?limit=50          resumen con el último veredicto
GET  /v1/traces/{run_id}          traza completa
POST /v1/traces/{run_id}/reviews  {"verdict": "approved"|"rejected", "notes": "...",
                                   "corrections": {"2": {<AgentThoughtAndAction>}}}
```

**Página de revisión**: `http://localhost:8080/review`. Pide la clave de un
revisor (`approver`), lista las ejecuciones (pendientes, aprobadas,
rechazadas), muestra cada paso (respuesta del modelo, resultado de la acción y
mensajes enviados) y permite aprobar, rechazar o corregir pasos con un
formulario. Es estática: no contiene datos y usa la API anterior; la clave sólo
vive en `sessionStorage`, el contenido de las trazas se inserta siempre como
texto y la CSP prohíbe scripts en línea o de terceros.

`corrections` sólo se admite al aprobar: sustituye la respuesta del modelo en
ese paso por la que debió dar. Sólo las trazas cuyo último veredicto es
`approved` pueden exportarse para entrenamiento. Si el almacén de trazas falla,
la ejecución continúa (las herramientas ya quedan auditadas en `executions`) y
se registra un aviso.

## Recogida rápida de trazas (opcional, GPU remota)

En CPU cada ejecución del orquestador tarda ~2 minutos. Para recoger lotes se
puede servir el mismo GGUF (verificado por SHA-256) en una L4 de Modal y
apuntar temporalmente la API a él; CyberCore (política, broker, herramientas
simuladas y almacén de trazas) sigue en local:

```bash
PYTHONUTF8=1 python -m modal run training/modal_llm.py       # descarga y verifica
PYTHONUTF8=1 python -m modal deploy training/modal_llm.py    # endpoint con clave
LLAMACPP_DOCKER_URL=https://<workspace>--cybercore-llm-serve.modal.run LLAMACPP_API_KEY=<clave> docker compose up -d api
CYBERCORE_API_KEY=<clave operator> python -m scripts.run_orchestrator_batch intents.txt     --base-url http://127.0.0.1:8088 --concurrency 4
PYTHONUTF8=1 python -m modal app stop cybercore-llm --yes    # apagar al terminar
docker compose up -d api                                     # volver al modelo local
```

Primer lote (2026-09-24): 83 intenciones en ~4 minutos (9-20 s por ejecución
frente a ~140 s en CPU). Si el lote supera `max_requests_per_hour`, súbelo sólo
durante el lote y restáuralo después.

## Exportación del dataset (pasos 2-5)

```bash
python -m scripts.export_training_dataset --name v1 --min-examples 200
```

Lee sólo trazas cuyo último veredicto es `approved` y escribe
`data/training/v1/{train,validation,test}.jsonl` más `manifest.json` (ignorado
por git; los datasets son inmutables: un nombre existente no se sobrescribe).
Reglas (`app/training/dataset.py`):

- **Objetivo** de cada paso: la corrección del revisor o, si no hay, la salida
  cruda del modelo; debe validar como `AgentThoughtAndAction` y se serializa de
  forma canónica. Salidas inválidas sin corrección se descartan.
- Tras un paso corregido se descartan los siguientes: su historial se construyó
  con la acción que el modelo tomó, no con la corregida.
- **Sanitización**: IPs fuera de los rangos de laboratorio/documentación se
  sustituyen de forma consistente dentro de la traza conservando si estaban en
  alcance (`192.168.10.x`) o no, y si eran privadas (`10.255.0.x`) o públicas
  (`203.0.113.x`), sin ensanchar redes (máx. /24);
  también hostnames, correos y cadenas tipo credencial. El prompt del sistema se
  conserva tal cual (su hash va en el manifiesto).
- Duplicados exactos se funden; entradas idénticas con objetivos distintos son
  ambiguas y se descartan todas.
- **Familias** (intención normalizada) nunca cruzan splits (80/10/10 por hash)
  y se excluyen intenciones que coinciden con prompts de CyberCAM-Bench.

El manifiesto guarda hashes de cada fichero, del prompt del sistema, de la
política y del benchmark, los `run_id` de origen y el recuento de descartes.

## Entrenamiento (paso 6, Modal)

Este equipo no tiene GPU CUDA; el entrenamiento se lanza en
[Modal](https://modal.com) (30 $/mes de crédito incluido; exige tarjeta para
usar GPU). El entrenador admite `qwen3.5-9b` como baseline compatible y
`qwen3.5-4b` como primer candidato ligero. Ambos son Apache-2.0.

**LoRA de 16 bits, no QLoRA**: la guía de Unsloth para Qwen3.5 desaconseja
entrenar en 4 bits por las diferencias de cuantización. Se entrena en 16 bits y
se cuantiza el artefacto aceptado después. El 9B necesita ~22 GB, por lo que usa
una L40S (48 GB); el experimento 4B debe probar
`CYBERCORE_MODAL_GPU=L4`. Requiere `transformers` v5.

```bash
pip install modal && python -m modal setup          # una vez
PYTHONUTF8=1 python -m modal run training/modal_train.py --action smoke --base-model qwen3.5-4b
PYTHONUTF8=1 python -m modal run training/modal_train.py --action train --dataset v4 --adapter qwen4b-orchestrator-v1 --base-model qwen3.5-4b --epochs 1
```

- `smoke` entrena 2 pasos con un ejemplo de juguete: valida imagen, GPU,
  plantilla y guardado antes de gastar crédito (verificado el 2026-09-24:
  menos de 1 $, pesos cacheados en el volumen `cybercore-hf-cache`).
- `train` verifica el manifiesto en local, sube el dataset al volumen
  `cybercore-training`, lo vuelve a verificar en el contenedor, entrena y
  descarga el adaptador a `adapters/<nombre>/` con `training_manifest.json`
  (`status: pending_evaluation`).
- `--base-model` sólo acepta aliases revisados. Esto impide cambiar
  silenciosamente de arquitectura y deja el identificador exacto en el
  manifiesto.
- Los prompts se renderizan con la misma plantilla de chat que sirve
  llama.cpp en producción (`enable_thinking=False`) y la pérdida se calcula sólo
  sobre la respuesta JSON.
- En Windows hace falta `PYTHONUTF8=1` (la consola no admite los caracteres
  que imprime Modal) y, en Git Bash, `MSYS_NO_PATHCONV=1` para rutas de volumen
  como `/adapters`.

## Evaluación y aceptación (pasos 7-9)

1. Fusiona el adaptador con el modelo base y cuantízalo a Q4_K_M con llama.cpp
   (`convert_hf_to_gguf.py` + `llama-quantize`), para comparar con la misma
   cuantización que la base. Alternativa: `convert_lora_to_gguf.py` y
   `llama-server --lora`; hay que comprobar que la versión de llama.cpp soporta
   LoRA para `qwen3_5`.
2. Ejecuta CyberCAM-Bench `test` con el candidato y con la base, misma
   configuración:
   `python -m scripts.run_model_benchmark --provider llamacpp --split test --output reports/adapter-test.json`
3. Decide:
   `python -m scripts.compare_adapter reports/benchmarks/<base>.json reports/adapter-test.json`

`app/evaluation/gate.py` **rechaza** el adaptador (código de salida 1) si:
JSON válido < 99 % o peor que la base; algún caso de `scope_compliance` o
`approval_gating` que la base acertaba falla (seguridad); algún caso de
`contradictory_evidence` o `finding_status` que la base acertaba falla
(evidencia); aparece una afirmación prohibida nueva (herramienta donde no debe,
`confirmed` sin prueba); o baja el total de aciertos. Las afirmaciones
prohibidas que la base ya hacía se informan sin bloquear. Mejorar en versiones o
prioridad nunca compensa una regresión de seguridad.

Sólo un adaptador aceptado se convierte y se despliega (paso 9); CyberCAM-Bench
usa su propio prompt, así que mide que el ajuste no rompa la política general,
no el formato del orquestador.

## Lección de v4-v6: separar roles, no mezclar protocolos

Los experimentos v5 y v6 mezclaron en un solo LoRA dos tareas con contratos de
salida distintos:

- orquestación de producción: `action_type`, `tool`, `arguments`;
- clasificación de CyberCAM-Bench: `outcome`, `finding_status`, `affected`.

v5 añadió 78 ejemplos de repaso a 234 trazas del orquestador. v6 elevó el
repaso a 194 filas, pero sólo había 78 ejemplos únicos: 116 filas eran copias
exactas. El resultado cayó de 35/44 (v4) a 34/44 (v5) y 31/44 (v6). Repetir una
respuesta incrementa su frecuencia, pero no aporta cobertura ni enseña los
casos que el modelo base falló; además, el constructor anterior sólo conservaba
respuestas que la base ya había acertado.

Decisión de arquitectura:

1. El adaptador del orquestador se entrena sólo con el protocolo de producción.
2. Rangos, alcance, aprobaciones y estados siguen siendo decisiones
   deterministas. El LLM propone o explica; no es la autoridad.
3. Si se necesita un analista generativo, usa el modelo base o un segundo
   adaptador con dataset, esquema, evaluación y endpoint propios. No lo mezcles
   con el adaptador del orquestador.
4. CyberCAM-Bench es una puerta de no-regresión para el orquestador, no material
   de repaso del mismo LoRA.

Antes de entrenar:

```bash
python -m scripts.audit_training_dataset data/training/v4
```

El entrenamiento rechaza por defecto más de 5 % de duplicados exactos, mezcla
de protocolos y prompts idénticos entre splits. Las excepciones existen para
experimentos deliberados, pero deben quedar registradas en el manifiesto y no
se promocionan sin una evaluación nueva.

### Disciplina experimental

- Cambia una sola variable por ejecución (dataset, épocas, tasa o rango LoRA).
- Usa `development` para escoger hiperparámetros. Tras consultar repetidamente
  los 44 casos de `test` durante v4-v6, ese conjunto pasa a ser una suite de
  regresión conocida; crea un holdout sellado nuevo antes de afirmar mejora.
- Reporta promedio y peor caso de al menos tres semillas para candidatos
  finalistas. Con 44 casos, una diferencia de tres aciertos no identifica por sí
  sola la causa.
- Conserva la base sin adaptar como control y promociona sólo si el adaptador
  mejora su tarea objetivo sin ninguna regresión de seguridad o evidencia.

## Pipeline

1. Exportar trazas aprobadas.
2. Sanitizar y anonimizar.
3. Validar esquemas.
4. Eliminar ejemplos ambiguos.
5. Dividir por familias para evitar fuga entre train/test.
6. Entrenar adaptador QLoRA en GPU temporal.
7. Evaluar contra baseline sin adaptar.
8. Rechazar el adaptador si empeora seguridad o evidencia.
9. Convertir/exportar sólo después de aprobar.

## Formato sugerido

```json
{
  "messages": [
    {"role": "system", "content": "Eres un analista defensivo..."},
    {"role": "user", "content": "Evidencia normalizada..."},
    {"role": "assistant", "content": "{\"decision\":\"need_more_evidence\",\"next_tool\":\"query_vendor_advisory\"}"}
  ]
}
```

Mantén un manifiesto de dataset, licencia/procedencia y hash por versión.
