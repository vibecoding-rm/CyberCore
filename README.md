# CyberCore

CyberCore es una base de trabajo defensiva para correlacionar inventario, vulnerabilidades, inteligencia actualizada y evidencia verificable mediante modelos locales intercambiables.

## Arquitectura resumida

```text
Telegram/Web -> FastAPI -> Policy Engine -> Tool Broker -> Adaptadores
                                |              |
                                |              +-> Nmap/Nuclei/Wazuh/Greenbone
                                +-> Scope, riesgo, aprobación y presupuestos

Evidencia -> PostgreSQL -> Analista especializado -> Informe/DefectDojo
```

El LLM propone acciones, pero no ejecuta comandos arbitrarios. Sólo puede solicitar herramientas con contratos definidos. Cada solicitud se valida contra alcance, nivel de riesgo, aprobación y presupuesto.

## Estado de este paquete

Este starter es un MVP seguro, no un producto terminado. Incluye una herramienta simulada para validar el flujo completo sin escanear redes. Los conectores reales se agregan después de superar las pruebas de políticas.

La Fase 0 fuerza `TOOL_MODE=mock`, aplica validación estricta y mantiene cerradas las
aprobaciones no verificables. Consulta
[`docs/07_FASE_0_CONTROLES.md`](docs/07_FASE_0_CONTROLES.md) para conocer los
controles implementados y cuáles sólo son válidos dentro de un proceso local.

## Comandos

```bash
make install
make test
make run
```

o con Docker:

```bash
cp .env.example .env
docker compose up --build
```

## Límites

- Uso exclusivo en activos propios o con autorización expresa.
- Redes públicas denegadas de forma predeterminada.
- Sin shell general para los modelos.
- Las acciones activas necesitan aprobación explícita.
- Una conclusión de vulnerabilidad requiere evidencia, no sólo la opinión de un modelo.

## Documentación

Empieza por `LEEME_PRIMERO.md` y `docs/00_GUIA_MAESTRA.md`.
