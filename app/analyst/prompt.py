"""Prompt and structured call for the LLM analyst (systems C1/C2 of Analyst-Bench)."""

from __future__ import annotations

import json
import time
from typing import Any

from pydantic import ValidationError

from app.analyst.contract import AnalystOutput
from app.api.models import EvidenceCaseBundle
from app.llm.base import ChatClient, LLMClientError

ANALYST_SYSTEM_PROMPT = """Eres el analista de CyberCore. Explicas un expediente de evidencia ya evaluado a un técnico de seguridad que no conoce el caso. Respondes en español y sólo con el JSON pedido.

Reglas:
1. Usa únicamente los datos del expediente. No añadas CVE, versiones, IPs, fechas, puntuaciones ni hechos que no aparezcan en él, aunque los conozcas.
2. El estado del hallazgo (candidate, probable o confirmed) lo decidió el motor determinista y es definitivo. Explícalo; no lo cambies ni lo discutas. Si no es confirmed, no digas que la vulnerabilidad está confirmada, demostrada o explotada.
3. Cada elemento de evidence_interpretation debe citar el evidence_id de una evidencia del expediente y decir qué muestra y qué no muestra.
4. En contradictions, describe los datos incompatibles (por ejemplo, una reproducción con una versión fuera de rango). Déjalo vacío si no los hay.
5. En missing_evidence, di qué comprobación concreta falta y por qué cambiaría la conclusión. Si el hallazgo no está confirmado, no puede quedar vacío.
6. recommended_actions: pasos defensivos, reversibles y concretos, en orden (actualizar, verificar la versión por otra fuente, aplicar mitigaciones, volver a validar con aprobación). Nunca propongas explotar, forzar credenciales, ampliar el alcance ni saltarse aprobaciones.
7. confidence_explanation: justifica el nivel de confianza con la evidencia disponible.
8. Un puerto abierto o una coincidencia de versión por sí solos no demuestran una vulnerabilidad; las distribuciones aplican parches sin cambiar la versión (backports)."""


def case_view(bundle: EvidenceCaseBundle) -> dict[str, Any]:
    """What the analyst (and the reviewer) sees: content without signature fields."""
    assessment = bundle.assessment
    return {
        "objetivo": bundle.target,
        "vulnerabilidad": bundle.vulnerability_snapshot or {"vulnerability_id": bundle.vulnerability_id},
        "evaluacion_del_motor": {
            "estado": assessment.finding_status,
            "conclusion": assessment.conclusion,
            "observaciones": assessment.observations,
            "evidencia_que_falta": [
                {"codigo": gap.code, "descripcion": gap.description,
                 "accion_recomendada": gap.recommended_action}
                for gap in assessment.missing_evidence
            ],
            "comparacion_de_versiones": [
                {"producto": m.product_key, "version_instalada": m.installed_version,
                 "veredicto": m.verdict, "notas": m.notes}
                for m in assessment.version_matches
            ],
            "evidencias_de_validacion": assessment.validation_evidence_ids,
        },
        "evidencias": [
            {"evidence_id": item.evidence_id, "fuente": item.source, "objetivo": item.target,
             "recogida": item.collected_at.isoformat(), "datos": item.data}
            for item in bundle.evidence
        ],
    }


def analyst_messages(bundle: EvidenceCaseBundle) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": "Expediente:\n" + json.dumps(
            case_view(bundle), ensure_ascii=False, indent=1
        )},
    ]


def _inline_refs(schema: Any, defs: dict[str, Any]) -> Any:
    if isinstance(schema, dict):
        if "$ref" in schema:
            return _inline_refs(defs[schema["$ref"].split("/")[-1]], defs)
        return {k: _inline_refs(v, defs) for k, v in schema.items() if k not in {"$defs", "title"}}
    if isinstance(schema, list):
        return [_inline_refs(item, defs) for item in schema]
    return schema


def analyst_response_schema() -> dict[str, Any]:
    """AnalystOutput as a self-contained schema, every field required, in contract order."""
    schema = AnalystOutput.model_json_schema()
    inlined = _inline_refs(schema, schema.get("$defs", {}))
    inlined["required"] = list(inlined["properties"])
    for prop in inlined["properties"].values():
        prop.pop("default", None)
    return inlined


async def run_llm_analyst(
    client: ChatClient, model: str, bundle: EvidenceCaseBundle, *, num_predict: int = 1500
) -> dict[str, Any]:
    """One analyst answer; errors are recorded, never raised, so a run completes."""
    started = time.perf_counter()
    record: dict[str, Any] = {"output": None, "error": None, "raw": None}
    try:
        completion = await client.chat_structured(
            model, analyst_messages(bundle), analyst_response_schema(),
            num_predict=num_predict,
        )
        record["raw"] = completion.content
        record["generated_tokens"] = completion.eval_count
        record["output"] = AnalystOutput.model_validate_json(completion.content).model_dump()
    except (LLMClientError, ValidationError, ValueError) as exc:
        record["error"] = str(exc)[:500]
    record["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return record
