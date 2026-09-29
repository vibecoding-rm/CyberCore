# Registro de uso del holdout de Analyst-Bench

Cada ejecución sobre `config/analyst_bench/holdout.jsonl` se anota aquí antes
de producir respuestas. Si un resultado motiva cambiar prompt, modelo o datos,
el holdout queda gastado y se genera otro con familias nuevas.

| Fecha | Run | Sistemas | Motivo |
|---|---|---|---|
| 2026-09-25 | 2026-09-25-holdout-9b | C1, C2 | Primera medición en holdout: plantilla frente al 9B con prompts v1 y v2 tras ajustar v2 en desarrollo |
| 2026-09-29 | 2026-09-29-holdout2-9b | C2 | Primera medición en holdout2: adopción v2 (pipeline con respaldo C0) del 9B con v2, en CPU |
| 2026-09-29 | 2026-09-29-holdout2-9b | C2 | Relanzamiento de la misma ejecución: el contenedor se reinició en el caso 7/60 y se perdieron las respuestas sin haberse leído; ahora con punto de control |
| 2026-09-29 | 2026-09-29-holdout2-9b | C2 | Reanudación: llama-server murió por falta de memoria (caché de prompts) tras el caso 28; se reintentan los 32 casos con error de conexión; respuestas sin leer |
