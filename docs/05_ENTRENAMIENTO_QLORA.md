# Entrenamiento posterior con QLoRA

## Cuándo hacerlo

No entrenes antes de que el sistema funcione con prompts, herramientas y evaluación. Primero necesitas ejemplos correctos producidos o revisados por humanos.

## Qué aprenderá el adaptador

- Elegir la herramienta adecuada.
- Interpretar la salida normalizada.
- Negarse a afirmar más de lo demostrado.
- Pedir la comprobación faltante.
- Distinguir afectado, no afectado y desconocido.
- Priorizar con contexto.
- Redactar findings con evidencia.

## Qué no aprenderá

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

`corrections` sólo se admite al aprobar: sustituye la respuesta del modelo en
ese paso por la que debió dar. Sólo las trazas cuyo último veredicto es
`approved` pueden exportarse para entrenamiento. Si el almacén de trazas falla,
la ejecución continúa (las herramientas ya quedan auditadas en `executions`) y
se registra un aviso.

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
  alcance (`192.168.10.x`) o no (`203.0.113.x`), sin ensanchar redes (máx. /24);
  también hostnames, correos y cadenas tipo credencial. El prompt del sistema se
  conserva tal cual (su hash va en el manifiesto).
- Duplicados exactos se funden; entradas idénticas con objetivos distintos son
  ambiguas y se descartan todas.
- **Familias** (intención normalizada) nunca cruzan splits (80/10/10 por hash)
  y se excluyen intenciones que coinciden con prompts de CyberCAM-Bench.

El manifiesto guarda hashes de cada fichero, del prompt del sistema, de la
política y del benchmark, los `run_id` de origen y el recuento de descartes.

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
