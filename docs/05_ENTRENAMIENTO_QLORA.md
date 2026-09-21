# Entrenamiento posterior con QLoRA

## Cuándo hacerlo

No entrenes antes de que el sistema funcione con prompts, herramientas y evaluación. Primero necesitas ejemplos correctos producidos o revisados por humanos.

## Qué aprenderá el adaptador

- Elegir la herramienta adecuada.
- Interpretar la salida normalizada.
- Negarse a afirmar más de lo demostrado.
- Pedir la comprobación faltante.
- Distinguir afectado, no afectado y desconocido.
- Priorizar con contexto.
- Redactar findings con evidencia.

## Qué no aprenderá

- Listas de CVE actuales.
- Valores EPSS.
- Catálogo KEV.
- Versiones actuales de productos.
- Secretos, IP internas reales o datos personales.

## Pipeline

1. Exportar trazas aprobadas.
2. Sanitizar y anonimizar.
3. Validar esquemas.
4. Eliminar ejemplos ambiguos.
5. Dividir por familias para evitar fuga entre train/test.
6. Entrenar adaptador QLoRA en GPU temporal.
7. Evaluar contra baseline sin adaptar.
8. Rechazar el adaptador si empeora seguridad o evidencia.
9. Convertir/exportar sólo después de aprobar.

## Formato sugerido

```json
{
  "messages": [
    {"role": "system", "content": "Eres un analista defensivo..."},
    {"role": "user", "content": "Evidencia normalizada..."},
    {"role": "assistant", "content": "{\"decision\":\"need_more_evidence\",\"next_tool\":\"query_vendor_advisory\"}"}
  ]
}
```

Mantén un manifiesto de dataset, licencia/procedencia y hash por versión.
