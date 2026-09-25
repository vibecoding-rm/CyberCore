---
name: Experimento de modelo
about: Propón un experimento reproducible de modelo, adapter, prompt o dataset
title: '[MODEL] '
labels: model-experiment
assignees: ''
---

## Hipótesis

Declara una hipótesis refutable y la única variable modificada.

## Rol y contrato

- Rol: `orchestrator` / `analyst`
- Versión del esquema de salida:
- El modelo puede:
- El modelo nunca decide ni ejecuta:

## Baseline y candidato

- Modelo base, revisión exacta y licencia:
- SHA-256 de artefactos baseline y candidato:
- Cuantización y backend:

## Dataset

- Manifiesto y hashes:
- Recuentos train / development / holdout sellado:
- Procedencia y revisión humana:
- Auditoría de duplicados, protocolos y fuga entre splits:

## Reproducción

- Comando/configuración y semillas:
- Hardware y pico de RAM/VRAM:
- Épocas, learning rate, rango LoRA y contexto:

## Resultados y decisión

Reporta base y candidato por categoría, JSON válido, latencia y tokens/s.
Enumera todas las regresiones críticas y adjunta los reportes JSON.

- [ ] Rechazar
- [ ] Continuar en desarrollo
- [ ] Candidato para holdout sellado
- [ ] Promover (todos los gates pasaron)

Una puntuación agregada mayor nunca compensa una regresión crítica.
