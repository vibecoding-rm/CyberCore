# Arquitectura técnica

## Componentes

| Componente | Responsabilidad | Confianza |
|---|---|---|
| API | Autenticación, solicitudes, estado | Alta |
| Policy Engine | Alcance, riesgo, aprobación, presupuestos | Crítica |
| Orquestador | Plan y selección de herramienta | No confiable por defecto |
| Tool Broker | Validación y ejecución controlada | Crítica |
| Adaptadores | Traducción a APIs/CLI permitidas | Alta, después de pruebas |
| Analista | Interpretación de evidencia | Consultiva |
| PostgreSQL | Estado estructurado y trazabilidad | Fuente interna |
| Fuentes externas | CVE, KEV, EPSS, OSV, advisories | Según procedencia |
| DefectDojo | Ciclo de vida de findings | Sistema de registro posterior |

## Fronteras de confianza

El contenido que llega de un escáner, advisory, web o LLM debe tratarse como datos no confiables. Nunca se concatena directamente en un comando. Los adaptadores construyen argumentos desde tipos validados y listas permitidas.

## Contrato mínimo de una herramienta

Cada herramienta debe declarar:

- Nombre estable.
- Propósito.
- Esquema de entrada.
- Campo que contiene el objetivo.
- Nivel de riesgo.
- Si necesita aprobación.
- Timeout.
- Límite de resultados.
- Salida normalizada.
- Evidencia original y hash.
- Versiones de herramienta y reglas/templates.

## Propuesta de despliegue futuro

```text
Nodo IA: FastAPI + modelos + broker
Nodo scanner: Nmap + Nuclei + Greenbone
Nodo endpoint/security: Wazuh
Nodo datos: PostgreSQL/pgvector
```

En el MVP pueden convivir algunos servicios, pero el diseño no debe suponer que todos vivirán siempre en una PC de 16 GB.

## Modelo de aprobación

La aprobación debe estar ligada a:

- Usuario.
- Herramienta.
- Objetivo exacto.
- Argumentos normalizados.
- Fecha de expiración.
- Uso único.

Un texto como “sí, aprueba todo” no debe convertirse en autorización indefinida.
