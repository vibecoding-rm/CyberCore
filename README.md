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

La Fase 0 fuerza `TOOL_MODE=mock`, aplica validación estricta y mantiene cerrados los
adaptadores reales. Consulta
[`docs/07_FASE_0_CONTROLES.md`](docs/07_FASE_0_CONTROLES.md) para conocer los
controles implementados y los límites operativos que aún permanecen.

## Comandos

```bash
make install
make create-api-key
make migrate
make test
make run
```

`make create-api-key` muestra una clave una sola vez y la línea con su hash que debe
guardarse en `.env`. La clave en claro se conserva fuera del repositorio y se envía
como `Authorization: Bearer <clave>`.

o con Docker:

```bash
cp .env.example .env
docker compose up --build
```

La API aplica las migraciones antes de arrancar en Docker. `GET /ready` devuelve
`200` sólo cuando la auditoría, la autenticación, las aprobaciones y el coordinador
de presupuestos están disponibles. Sin `API_CREDENTIALS_JSON`, el servicio
permanece cerrado por defecto.

Las herramientas marcadas con `approval_required` sólo aceptan tokens emitidos por
`POST /v1/approvals`. La emisión requiere una identidad con rol `approver`, debe
autorizar a otra identidad `operator` y queda ligada a la herramienta, los argumentos
canónicos y una expiración. El token se consume de forma atómica una sola vez.

La cuota horaria y la concurrencia máxima se coordinan en PostgreSQL y se comparten
entre workers. Los slots son leases con expiración basada en el reloj de la base de
datos, de modo que un proceso caído no bloquee capacidad de forma permanente.

La primera demostración funcional está disponible en `POST
/v1/analysis/inventory`. Ejecuta únicamente el inventario simulado autorizado y
devuelve un análisis determinista de la evidencia faltante. Una afirmación o un CVE
aportado por el usuario nunca bastan para marcar el activo como vulnerable.

```bash
curl -s -X POST http://127.0.0.1:8080/v1/analysis/inventory \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${CYBERCORE_API_KEY}" \
  -d '{"target":"192.168.10.25","vulnerability_id":"CVE-2026-99999"}'
```

## Límites

- Uso exclusivo en activos propios o con autorización expresa.
- Redes públicas denegadas de forma predeterminada.
- Sin shell general para los modelos.
- Las acciones activas necesitan aprobación explícita.
- Una conclusión de vulnerabilidad requiere evidencia, no sólo la opinión de un modelo.

## Documentación

Empieza por `LEEME_PRIMERO.md` y `docs/00_GUIA_MAESTRA.md`.
