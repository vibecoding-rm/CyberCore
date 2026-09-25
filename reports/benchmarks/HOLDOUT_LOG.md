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
