from typing import Any, Literal
from uuid import UUID, uuid4
from pydantic import BaseModel, ConfigDict, Field


class AgentThoughtAndAction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    thought: str = Field(
        ...,
        description="Razonamiento defensivo sobre el estado actual, el alcance y lo que falta comprobar",
    )
    action_type: Literal["call_tool", "final_answer"] = Field(
        ...,
        description="'call_tool' para ejecutar una herramienta disponible, o 'final_answer' para concluir",
    )
    tool: str | None = Field(
        default=None,
        description="Nombre de la herramienta si action_type='call_tool': 'discover_hosts', 'inspect_services', o 'get_mock_inventory'",
    )
    arguments: dict[str, Any] | None = Field(
        default=None,
        description="Argumentos estructurados para la herramienta seleccionada",
    )
    final_summary: str | None = Field(
        default=None,
        description="Resumen final detallado para el operador si action_type='final_answer'",
    )


class AgentStep(BaseModel):
    step_number: int
    thought: str
    action_type: str
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    observation: str
    evidence_sha256: str | None = None


class AgentRunResult(BaseModel):
    run_id: UUID = Field(default_factory=uuid4)
    operator_intent: str
    status: Literal["completed", "approval_required", "denied", "error"]
    steps: list[AgentStep] = Field(default_factory=list)
    discovered_assets: list[dict[str, Any]] = Field(default_factory=list)
    pending_approval: dict[str, Any] | None = None
    final_report: str


class OrchestratorRunRequest(BaseModel):
    intent: str = Field(..., min_length=3, description="Instrucción u objetivo del operador en lenguaje natural")
    approval_token: str | None = Field(default=None, description="Token de aprobación previa si la acción lo requiere")
