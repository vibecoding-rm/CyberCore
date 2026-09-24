# Adaptadores LoRA del orquestador

Modelo base `Qwen/Qwen3.5-9B`, LoRA de 16 bits (Unsloth) en una L40S de Modal,
2 épocas. Evaluación estructural en el split `test` del propio dataset (nunca
visto al entrenar): JSON válido, `action_type`, herramienta y objetivo frente a
la respuesta revisada. El texto libre no se puntúa.

| Adaptador | Dataset | Ejemplos (train/val/test) | Pérdida val. | Base | Adaptador | Estado |
|---|---|---|---|---|---|---|
| v1 | v1 | 207/12/21 | 0,143 | — | — | **No usar**: 49 trazas aprobadas en bloque sin revisar (datos inventados, autorización por chat, objetivos ampliados) y prompt antiguo |
| v2 | v2 | 179/12/17 | 0,099 | 13/17 (76 %) | 16/17 (94 %) | Sustituido por v3 (sanitizador v1) |
| v3 | v3 | 179/12/17 | 0,099 | 15/17 (88 %) | 16/17 (94 %) | Pendiente del gate de CyberCAM-Bench |

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

## Antes de desplegar un adaptador

1. Dar al orquestador el alcance autorizado de forma explícita (generado desde
   `PolicyEngine`) para que no tenga que memorizarlo, o variar las redes de
   laboratorio en los datos.
2. Pasar el gate de CyberCAM-Bench: fusionar, convertir a GGUF Q4_K_M, servir y
   comparar con `scripts/compare_adapter` frente a la base.
3. Más datos y más variados; el split `test` actual es pequeño.
