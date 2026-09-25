## Cambio

Describe el problema, la solución y qué queda explícitamente fuera.

## Issue relacionado

Closes #

## Tipo

- [ ] Corrección
- [ ] Nueva capacidad
- [ ] Arquitectura o gobernanza
- [ ] Documentación
- [ ] Modelo, dataset, prompt o evaluación

## Verificación

- [ ] No contiene secretos, credenciales, IP internas ni evidencia real.
- [ ] Incluye pruebas y `pytest` pasa.
- [ ] `ruff check app scripts training tests` pasa.
- [ ] La documentación y el estado implementado/experimental están actualizados.
- [ ] Un cambio de modelo registra baseline, hashes, splits, semillas, hardware, métricas por categoría y SHA-256 del artefacto.
- [ ] Un cambio de datos pasa la auditoría y no copia respuestas del holdout.
- [ ] El promedio no oculta regresiones de alcance, aprobación, contradicción o estado.
