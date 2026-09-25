# Registro de uso de CyberCAM-Holdout

`config/benchmark_holdout.yaml` (104 casos, generado por
`scripts/generate_holdout.py`, SHA-256 `0a298a723db23bf44e17e20dd7faeb2da5d5f25956c453c7ed226a1bd55d632d`) es el conjunto sellado para
comparar finalistas. El split `test` de CyberCAM-Bench se consultó en cada
iteración de los adaptadores v4–v6 y ya es una suite de regresión conocida.

Reglas:

1. No se usa para elegir prompts, hiperparámetros, datasets ni plantillas.
   Para eso están `train` y `development`.
2. Cada ejecución se anota aquí antes de mirar el resultado: fecha, modelo,
   hardware, motivo e informe JSON.
3. Si un resultado del holdout motiva un cambio en el modelo o el prompt, el
   holdout queda gastado: se genera uno nuevo con otra semilla y otros textos.

Limitación conocida: los 12 casos de `finding_status` son todos
`candidate`/`probable`; las combinaciones que llevan a `confirmed` ya
están en CyberCAM-Bench.

| Fecha | Modelo | Hardware | Motivo | Informe |
|---|---|---|---|---|
| 2026-09-25 | Qwen3.5-9B Q4_K_M (base) | Ryzen 5 5500, 16 GB, CPU, llama.cpp ctx 8192 | M0: baseline frente al 4B | `2026-09-25-qwen3.5-9b-q4km-holdout-m0-cpu.json` |
| 2026-09-25 | Qwen3.5-4B Q4_K_M (base) | Ryzen 5 5500, 16 GB, CPU, llama.cpp ctx 8192 | M0: candidato ligero | `2026-09-25-qwen3.5-4b-q4km-holdout-m0-cpu.json` |

Resultados de M0: 9B 84/104, 4B 68/104 ([informe](2026-09-25-M0.md)). La
decisión fue no adoptar el 4B; no se cambió ningún modelo ni prompt a partir
del holdout. Los fallos individuales se inspeccionaron para el informe, así
que no deben usarse para ajustar prompts: si se hiciera, el holdout quedaría
gastado.
