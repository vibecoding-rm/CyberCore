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
