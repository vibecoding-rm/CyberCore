# Modelo analista local ligero

## Decisión de producto

CyberCore construye un **analista local de vulnerabilidades para redes y equipos
autorizados**, no un chatbot general ni un escáner nuevo. Las herramientas
existentes recolectan evidencia; CyberCore controla su ejecución, correlaciona
los resultados y produce un expediente verificable sin enviar datos a servicios
externos.

El producto debe trabajar sin Internet durante el análisis normal, ejecutarse
en 16 GB de RAM, limitarse a activos autorizados, explicar evidencia en español,
abstenerse cuando falten pruebas y dejar las decisiones críticas a código.

El 9B Q4_K_M actual (5,7 GB) ya cabe en 16 GB. El motivo para probar 3–4B es
la latencia en CPU: el 9B tarda unos 23 s por caso de CyberCAM-Bench en el
equipo de desarrollo (`reports/benchmarks/2026-09-25-qwen3.5-9b-q4km-development-m0-cpu.json`).
Un modelo menor sólo se adopta si M0 demuestra que no pierde seguridad.

No vamos a preentrenar un modelo desde cero. Sería mucho más costoso y volvería
a enseñarle lenguaje y conocimiento general que ya existe. Especializaremos un
modelo abierto de 3–4B parámetros con LoRA y datos propios revisados.

## Arquitectura objetivo

```text
petición -> guardas deterministas -> orquestador LoRA -> ToolBroker
                                                     -> evidencia sellada
evidencia + fuentes + activo -> analista LoRA -> explicación/recomendación
                            -> motor determinista -> estado/prioridad final
```

Se usa un solo modelo base y dos adaptadores intercambiables:

- `orchestrator`: selecciona una herramienta registrada y construye su llamada
  JSON. No clasifica hallazgos.
- `analyst`: interpreta evidencia normalizada. No ejecuta herramientas ni
  asigna el estado autoritativo del hallazgo.

No se mezclan protocolos en un adaptador. El broker, `PolicyEngine`, el
comparador de versiones, las aprobaciones, hashes y estados siguen siendo
código. El modelo tampoco almacena CVE ni feeds en sus pesos: los recibe desde
la base local con fuente y fecha.

## Candidatos de primera ronda

| Prioridad | Modelo | Motivo | Condición |
|---|---|---|---|
| 1 | `Qwen/Qwen3.5-4B` | Continuidad con el 9B, Apache 2.0, 4B y multilingüe | Igualar seguridad y JSON del 9B |
| 2 | `mistralai/Ministral-3-3B-Instruct-2512-BF16` | 3.4B de lenguaje, español, JSON, Apache 2.0 y menos de 8 GB cuantizado según su tarjeta | Verificar llama.cpp y formato de herramientas |
| 3 | `microsoft/Phi-4-mini-instruct` | 3.8B, MIT y español evaluado | Su tarjeta advierte alucinaciones de funciones |
| Referencia | `fdtn-ai/Foundation-Sec-8B-Reasoning` | 8B especializado para comparar análisis | Sólo inglés y licencia remitida a `NOTICE.md` |

Fuentes primarias: [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B),
[Ministral 3 3B](https://huggingface.co/mistralai/Ministral-3-3B-Instruct-2512-BF16),
[Phi-4-mini](https://huggingface.co/microsoft/Phi-4-mini-instruct) y
[Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning).
Una tarjeta no sustituye la evaluación en CyberCore.

## Contrato del analista

La entrada contiene activo, observaciones con `evidence_id`, producto y versión
observados, advisory local, rangos afectados, fecha de fuente, KEV/EPSS,
exposición y validación independiente si existe.

```json
{
  "summary": "Qué muestra realmente la evidencia",
  "evidence_interpretation": ["observación vinculada a evidence_id"],
  "contradictions": ["datos incompatibles"],
  "missing_evidence": ["comprobación concreta que falta"],
  "recommended_actions": ["acción defensiva y reversible"],
  "confidence_explanation": "por qué la conclusión es limitada"
}
```

La salida no incluye `finding_status`, `affected`, `priority`, `approval` ni
llamadas de herramienta. Esos campos pertenecen a motores deterministas o al
adaptador del orquestador.

## Dataset del analista

No se obtiene duplicando casos del benchmark. Cada ejemplo conserva procedencia
y proviene de expedientes sintéticos producidos por las reglas, laboratorio
autorizado y anonimizado, o casos reales revisados por una persona. Debe incluir
casos difíciles: evidencia contradictoria, versión ausente, backport, servicio
expuesto/no expuesto, validación negativa y falso positivo.

Cada familia de activo o vulnerabilidad queda en un único split. El mismo CVE,
plantilla o paráfrasis no puede aparecer a ambos lados de train/holdout. Las
correcciones humanas valen más que repetir ejemplos. Se versionan manifiesto,
licencia/procedencia, hashes, esquema y revisión.

Primera meta: 800–1.500 ejemplos únicos y balanceados para el piloto, con al
menos 200 casos sellados que nunca se usen para ajustar prompts o
hiperparámetros. Es una hipótesis de trabajo, no una garantía: el gate decide si
hacen falta más datos.

## Entrenamiento y evaluación

1. Ejecutar los modelos base sin adaptar con el mismo hardware y cuantización.
2. Elegir el menor que supere los gates; no elegirlo por benchmarks generales.
3. Entrenar LoRA con pérdida sólo sobre la respuesta. TRL soporta
   `completion_only_loss`; PEFT mantiene adaptadores pequeños y conmutables.
4. Empezar con una época, tres semillas y una variable por experimento.
5. Evaluar en holdout sellado, CyberCAM-Bench y pruebas adversariales.
6. Cuantizar sólo el candidato aceptado y repetir las pruebas sobre el GGUF.

Fuentes: [TRL SFTTrainer](https://huggingface.co/docs/trl/sft_trainer) y
[PEFT LoRA](https://huggingface.co/docs/peft/en/package_reference/lora).

Gates obligatorios:

- 100 % de cumplimiento de alcance y aprobación;
- 100 % de JSON válido bajo el esquema de producción;
- cero `confirmed` sin las pruebas deterministas requeridas;
- cero CVE o `evidence_id` inexistentes;
- ninguna regresión en contradicción y abstención;
- mejora repetible en la tarea objetivo;
- RAM pico, latencia y tokens/s registrados en el equipo de 16 GB.

## Roadmap ejecutable

### M0 — baseline pequeño

Resultado 2026-09-25 ([informe](../reports/benchmarks/2026-09-25-M0.md)): el
4B no se promueve (68/104 frente a 84/104 y seis fallos de alcance o
aprobación frente a uno). El 9B sigue siendo la base; queda por medir
Ministral 3 3B.

- Ejecutar Qwen3.5-4B Q4 y el 9B actual sobre CyberCAM-Bench.
- Medir precisión por categoría, RAM, latencia y tokens/s.
- Promover el 4B sólo si no introduce regresiones críticas.

### M1 — contrato del analista

- Implementar el esquema anterior y un endpoint sin permisos de ejecución.
- Crear `Analyst-Bench` separado del benchmark del orquestador. Diseño,
  puerta automática y control sin modelo: [`09_ANALYST_BENCH.md`](09_ANALYST_BENCH.md).
- Exportar paquetes de evidencia sintéticos con respuestas revisadas.

### M2 — primer adaptador

- Reunir datos únicos, auditar fugas y entrenar una época.
- Comparar tres semillas y publicar todos los fallos.
- Probar Qwen3.5-4B y luego Ministral 3 3B sin cambiar también el dataset.

### M3 — piloto empresarial

- Integrar Wazuh/Greenbone en modo de sólo lectura en laboratorio.
- Validar recomendaciones con un analista humano.
- Aprender sólo de correcciones aprobadas, nunca de respuestas autogeneradas
  sin revisión.

## Diferenciación

Ya existen escáneres, SIEM y modelos de ciberseguridad. CyberCore no intenta
reemplazarlos: los une en un analista pequeño, local, evidence-first y auditable.
Su valor es producir una explicación y un expediente reproducible bajo
políticas que el modelo no puede modificar. Esa combinación de privacidad,
controles deterministas, abstención y evidencia portable es lo que debe validar
el piloto.
