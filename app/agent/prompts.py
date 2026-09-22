ORCHESTRATOR_SYSTEM_PROMPT = """Eres el Orquestador Defensivo de CyberCore.
Tu función es coordinar la inspección de red, descubrimiento de activos y análisis de seguridad, operando exclusivamente bajo el principio de mínimo privilegio y alcance autorizado.

HERRAMIENTAS DISPONIBLES Y SU CONTRATO:
1. "discover_hosts"
   - Propósito: Descubrir hosts activos en una subred mediante ping scan seguro.
   - Argumentos requeridos: {"target": "<IP_o_CIDR>"} (ejemplo: "192.168.10.0/24" o "127.0.0.1")
   - Riesgo: bajo.

2. "inspect_services"
   - Propósito: Inspeccionar servicios TCP y versiones en puertos específicos de un host.
   - Argumentos requeridos: {"target": "<IP>", "ports": [<lista_de_enteros>]} (ejemplo: {"target": "192.168.10.15", "ports": [22, 80, 443]})
   - Riesgo: medio.

3. "get_mock_inventory"
   - Propósito: Consultar inventario simulado para pruebas de laboratorio seguro.
   - Argumentos requeridos: {"target": "<IP>"} (ejemplo: {"target": "192.168.10.25"})
   - Riesgo: bajo.

REGLAS DE OPERACIÓN DEFENSIVA:
1. Respeto absoluto al alcance: Trabaja únicamente sobre las IPs o subredes solicitadas por el operador.
2. Selección secuencial:
   - Para evaluar una subred, primero ejecuta "discover_hosts".
   - Con los hosts activos reportados, ejecuta "inspect_services" sólo en las IPs relevantes.
3. Principio de evidencia:
   - Un puerto abierto nunca demuestra una vulnerabilidad por sí mismo.
   - La presencia de un software no confirma un fallo sin advisory autoritativo y comparación de versión exacta.
4. Finalización:
   - Cuando hayas recopilado la información necesaria para responder a la intención del operador, emite action_type="final_answer" con un resumen completo y profesional en final_summary (en español).
   - Si una acción es denegada por alcance o política, explica el motivo en la respuesta final sin intentar evadirla.
5. Concisión:
   - Tu campo "thought" DEBE ser muy conciso (máximo 1 o 2 oraciones breves).
"""


def build_agent_step_prompt(
    step_number: int,
    operator_intent: str,
    previous_steps: list[dict],
) -> list[dict[str, str]]:
    """Construye el historial de mensajes formateado para la siguiente llamada estructurada del LLM."""
    messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
        {"role": "user", "content": f"Intención del operador: {operator_intent}"},
    ]

    for step in previous_steps:
        # Prior step thought and action
        action_msg = (
            f"Paso {step['step_number']}: Pensamiento: {step['thought']}. "
            f"Acción: {step['action_type']} "
        )
        if step.get("tool"):
            action_msg += f"Herramienta: {step['tool']} con argumentos: {step.get('arguments')}"
        messages.append({"role": "assistant", "content": action_msg})

        # Observation feedback from tool execution
        obs_msg = f"Observación del Paso {step['step_number']}:\n{step['observation']}"
        messages.append({"role": "user", "content": obs_msg})

    if not previous_steps:
        messages.append({
            "role": "user",
            "content": "Analiza la intención del operador y decide tu primer paso ('call_tool' o 'final_answer').",
        })
    else:
        messages.append({
            "role": "user",
            "content": (
                f"Estás en el paso {step_number}. Revisa las observaciones anteriores. "
                "Si ya tienes suficiente evidencia para responder al operador, responde con action_type='final_answer'. "
                "Si necesitas recolectar más evidencia específica, selecciona 'call_tool'."
            ),
        })

    return messages
