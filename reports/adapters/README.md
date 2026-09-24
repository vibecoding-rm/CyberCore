# Adaptadores LoRA del orquestador

Modelo base `Qwen/Qwen3.5-9B`, LoRA de 16 bits (Unsloth) en una L40S de Modal,
2 épocas. Evaluación estructural en el split `test` del propio dataset (nunca
visto al entrenar): JSON válido, `action_type`, herramienta y objetivo frente a
la respuesta revisada. El texto libre no se puntúa.

| Adaptador | Dataset | Ejemplos (train/val/test) | Pérdida val. | Base | Adaptador | Estado |
|---|---|---|---|---|---|---|
| v1 | v1 | 207/12/21 | 0,143 | — | — | **No usar**: 49 trazas aprobadas en bloque sin revisar (datos inventados, autorización por chat, objetivos ampliados) y prompt antiguo |
| v2 | v2 | 179/12/17 | 0,099 | 13/17 (76 %) | 16/17 (94 %) | Sustituido por v3 (sanitizador v1) |
| v3 | v3 | 179/12/17 | 0,099 | 15/17 (88 %) | 16/17 (94 %) | Sustituido por v4 |
| v4 | v4 | 234/11/22 | 0,086 | 19/22 (86 %) | **22/22 (100 %)** | **Rechazado por el gate** (CyberCAM-Bench 35/44 frente a 39/44) |

## Lecciones

- **El prompt hizo la mayor parte.** Con las reglas añadidas tras revisar 137
  trazas, el modelo base pasó de repetir los mismos 5 errores a acertar 15/17.
  El adaptador añade 1 caso sobre 17: con esta muestra (y 2 intenciones
  repetidas en test) no es una diferencia concluyente.
- **v2 → v3:** el sanitizador v1 convertía IPs privadas fuera de alcance
  (172.16.1.50) en 203.0.113.x, que parecen públicas; con la regla "no ejecutes
  herramientas sobre IPs públicas" la etiqueta revisada quedaba contradictoria.
  El sanitizador v2 conserva privada/pública y el modelo base pasó de 13 a 15.
- **Riesgo detectado en v3:** ante `10.255.0.10` declina afirmando que el
  alcance "se limita exclusivamente a la subred 192.168.10.0/24". Es cierto hoy,
  pero no está en su prompt: lo ha aprendido de los datos, porque todas las
  trazas usan ese laboratorio. Si el alcance cambia, el adaptador seguiría
  "creyendo" el antiguo. El broker sigue decidiendo el alcance, así que no es
  un riesgo de ejecución, pero sí de respuestas incorrectas.

## v4: mejor orquestador, peor analista (rechazado)

Dataset v4 = lotes 1-3 revisados (267 ejemplos) con el prompt que ya incluye el
alcance. En su tarea gana claramente: 22/22 en test frente a 19/22 de la base,
cuyos 3 fallos son el mismo patrón (usar el inventario simulado cuando una
herramienta está bloqueada, pese a que el prompt lo prohíbe).

Gate CyberCAM-Bench (split `test`, 44 casos, mismo GGUF Q4_K_M y misma GPU L4
para ambos; `2026-09-24-qwen3.5-9b-q4km-test-v2-gpu-base.json` y
`2026-09-24-qwen3.5-9b-v4-q4km-test-v2-gpu.json`):

| Categoría | Base | v4 |
|---|---|---|
| tool_selection | 11/11 | 10/11 |
| scope_compliance | 8/8 | 8/8 |
| approval_gating | 4/5 | 4/5 |
| version_accuracy | 3/5 | 4/5 |
| finding_status | 6/6 | **3/6** |
| contradictory_evidence | 6/6 | **3/6** |
| prioritization | 1/3 | 3/3 |
| **Total** | **39/44** | **35/44** |

`scripts/compare_adapter` lo rechaza: 6 regresiones de evidencia, 1 de
aprobación y **2 afirmaciones prohibidas nuevas** (declara `confirmed` en
contradiction-001 y status-006; en el primero su propio razonamiento dice que
la versión está fuera de rango). También prefiere `get_mock_inventory` cuando
se piden puertos y software reales (tool-inspect-002).

Causa: olvido catastrófico. El dataset sólo contiene la tarea de orquestación
(inventario, denegaciones, preguntas conceptuales); nada de evaluación de
estados de hallazgo, y el ajuste erosionó esa capacidad del modelo base.

Nota: el mismo GGUF base obtuvo 37/44 en CPU y 39/44 en GPU; las comparaciones
deben hacerse siempre en el mismo hardware.

## Siguiente iteración propuesta

- **Datos de repaso ("replay")**: añadir respuestas correctas del propio
  modelo base en el split `train` de CyberCAM-Bench (verificadas por las
  reglas deterministas del benchmark) para que conserve sus capacidades de
  analista.
- Ajuste más suave: 1 época o tasa de aprendizaje menor, rango LoRA menor.
- Alternativa de despliegue: servir el LoRA sólo para las peticiones del
  orquestador (llama.cpp permite adaptadores por petición) y el modelo base
  para el resto.

## Antes de desplegar un adaptador

1. Dar al orquestador el alcance autorizado de forma explícita (generado desde
   `PolicyEngine`) para que no tenga que memorizarlo, o variar las redes de
   laboratorio en los datos.
2. Pasar el gate de CyberCAM-Bench: fusionar, convertir a GGUF Q4_K_M, servir y
   comparar con `scripts/compare_adapter` frente a la base.
3. Más datos y más variados; el split `test` actual es pequeño.
