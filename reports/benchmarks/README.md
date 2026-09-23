# Resultados de CyberCAM-Bench

Modelo: `Qwen3.5-9B-Q4_K_M.gguf` (unsloth, SHA-256 `03b74727…b7e8`) servido con
llama.cpp (`llama-server`, contexto 8192, CPU, ~5,6 GiB RAM, ~4 tokens/s).

## Split `development` (34 casos)

| Ejecución | Esquema de respuesta | Aciertos | JSON válido |
|---|---|---|---|
| v1 | plano, `reason` al final | 21/34 (61,8 %) | 91,2 % |
| v2 | plano, `reason` primero, todos los campos obligatorios | 22/34 (64,7 %) | 91,2 % |
| v3 | `oneOf` por `outcome`, `reason` primero | **28/34 (82,4 %)** | **100 %** |

| Categoría | v1 | v2 | v3 |
|---|---|---|---|
| tool_selection | 6/8 | 7/8 | 8/8 |
| scope_compliance | 7/7 | 7/7 | 7/7 |
| contradictory_evidence | 5/6 | 4/6 | 5/6 |
| prioritization | 0/3 | 1/3 | 3/3 |
| finding_status | 0/3 | 2/3 | 2/3 |
| version_accuracy | 3/7 | 1/7 | 3/7 |

Lecciones:

- v1: con `reason` al final, el modelo dejaba vacíos campos que su propio
  razonamiento resolvía bien (p. ej. `priority`).
- v2: exigir todos los campos le hizo rellenar campos ajenos a la pregunta
  (herramienta en una denegación, estado de hallazgo en una pregunta de versión).
- v3: una variante por `outcome` con sólo sus campos eliminó los fallos de
  estructura; lo que queda son errores de razonamiento del modelo.

Errores persistentes relevantes: declarar `confirmed` con inventario simulado
(status-008, 2 de 3 ejecuciones) e invertir una comparación de límite exclusivo
(version-015). Ambos quedan cubiertos por las reglas deterministas
(`decide_status`, `evaluate_range`): el modelo no decide estados ni rangos.

## Split `test`

Ver `2026-09-23-qwen3.5-9b-q4km-test.json` (una única ejecución, sin ajustes
posteriores).
