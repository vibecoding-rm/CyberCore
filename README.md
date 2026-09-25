# CyberCore

<p align="center">
  <strong>Analista defensivo local de vulnerabilidades, basado en evidencia</strong><br>
  <em>Gobernanza estricta de alcance, herramientas mediadas por un broker y expedientes de evidencia firmados.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue?logo=python" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/PostgreSQL-16%20%2B%20pgvector-336791?logo=postgresql" alt="PostgreSQL 16">
  <img src="https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/llama.cpp-Local%20Inference-black" alt="llama.cpp">
  <a href="https://github.com/vibecoding-rm/CyberCore/actions/workflows/ci.yml"><img src="https://github.com/vibecoding-rm/CyberCore/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="License">
</p>

---

## 🛡️ ¿Qué es CyberCore?

**CyberCore** no es una "IA que hackea". Es un analista defensivo local diseñado para operar en infraestructura propia o con autorización estricta. Resuelve el principal problema de los agentes de seguridad: **la falta de control, la alucinación de vulnerabilidades y la ejecución arbitraria de comandos**.

En CyberCore:
1. **La evidencia decide; el modelo explica y organiza.**
2. **Ningún LLM tiene acceso directo a una shell.** Toda interacción ocurre mediante contratos tipados y estrictamente validados en [ToolBroker](app/core/tool_broker.py).
3. **El alcance es inmutable:** [PolicyEngine](app/core/policy.py), aplicado por el broker a los argumentos de cada herramienta, rechaza de forma determinista cualquier IP pública o red fuera de los CIDRs autorizados. Esa es la frontera de seguridad.
   Antes de llamar al modelo, un filtro heurístico ([intent_guard](app/core/intent_guard.py)) deniega pronto las peticiones que piden operar sobre una IPv4 fuera de alcance, también si viene en Base64. No reconoce nombres de host ni paráfrasis; por eso no sustituye al broker.
4. **Trazabilidad auditable:** cada solicitud y decisión de política queda registrada en PostgreSQL, y la evidencia de cada herramienta se sella con **SHA-256**, se guarda en una tabla de sólo inserción y se reverifica al leerla. Los expedientes exportados van **firmados con Ed25519** por el servidor y se verifican sin conexión con su clave pública.
5. **Aprobaciones de un solo uso:** las acciones de riesgo medio o alto requieren un token aleatorio emitido por un aprobador distinto del operador, ligado a la herramienta y argumentos exactos y consumido atómicamente.
6. **El modelo no decide estados:** rangos de versión, estado del hallazgo (`candidate` → `confirmed`) y prioridad se calculan con reglas deterministas.

---

## 📐 Arquitectura del Sistema

```text
┌──────────────────────────────────────────────────────────────────┐
│                      Operador / Cliente API                      │
│            (Lenguaje natural / REST con Bearer Token)            │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│        Filtro de alcance previo (heurístico, sin modelo)         │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│          Orquestador LLM local (hoy: Qwen3.5-9B GGUF, base)      │
│      Elige una herramienta registrada y construye su JSON        │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Solicitud estructurada
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                           Tool Broker                            │
│   ├── Validación de Alcance (PolicyEngine: CIDRs permitidos)     │
│   ├── Control de Presupuestos (Leases distribuidos en Postgres)  │
│   ├── Verificación de Aprobaciones (Tokens de un solo uso)       │
│   └── Registro Durable de Auditoría (PostgresExecutionJournal)   │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Invocación aislada
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Adaptadores de Ejecución                     │
│   ├── discover_hosts      -> Nmap Ping Scan seguro (-sn -n)      │
│   ├── inspect_services    -> Nmap Service Banner (-sT -sV -Pn)   │
│   ├── run_nuclei_safe     -> Plantillas HTTP fijadas por SHA-256 │
│   ├── get_wazuh_inventory -> Paquetes/SO/puertos vía API Wazuh   │
│   ├── start_greenbone_task / get_greenbone_results (GMP)         │
│   └── get_mock_inventory  -> Entorno sintético de laboratorio    │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Evidencia cruda + SHA-256
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│             Persistencia e Inteligencia (PostgreSQL)             │
│   ├── assets & services   -> Inventario observable actualizado   │
│   ├── vulnerabilities     -> KEV + EPSS + NVD/OSV (rangos)      │
│   └── evidence & findings -> Evaluación con EvidenceGapAnalyzer  │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Evidencia sellada
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│   Motor determinista: rangos, estado del hallazgo y prioridad    │
│   -> expediente portable firmado (Ed25519)                       │
│   (planificado: analista LLM que sólo explica, sin ejecutar)     │
└──────────────────────────────────────────────────────────────────┘
```

Hoy el único modelo en uso es el orquestador base, sin adaptadores: los
adaptadores LoRA v4–v6 no pasaron el gate de CyberCAM-Bench
([informe](reports/adapters/README.md)). El modelo base ligero de 3–4B y el
analista LLM son la dirección de trabajo, no capacidades terminadas
([estado](docs/README.md)).

---

## 🚀 Inicio Rápido (Quickstart)

### Prerrequisitos
- Python 3.12 o superior.
- Docker y Docker Compose.
- Git.

### 1. Clonar el repositorio y configurar entorno
```bash
git clone https://github.com/vibecoding-rm/CyberCore.git
cd CyberCore

# Crear entorno virtual
python -m venv .venv

# Activar en Linux/macOS:
source .venv/bin/activate
# O en Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno desde la plantilla segura
cp .env.example .env
```

### 2. Levantar la infraestructura local con Docker
Inicia PostgreSQL (con extensión `pgvector`):
```bash
docker compose up -d postgres
```

Descarga el modelo orquestador (GGUF, ~5,7 GB) en `models/` y arranca llama.cpp:
```bash
mkdir -p models
curl -L -C - -o models/Qwen3.5-9B-Q4_K_M.gguf \
  https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q4_K_M.gguf
docker compose --profile llamacpp up -d llamacpp
```

### 3. Migrar la base de datos y sembrar inteligencia base
```bash
# Aplica las migraciones DDL
python scripts/migrate_db.py

# Siembra el catálogo base de vulnerabilidades KEV y EPSS
python scripts/ingest_vulnerabilities.py --baseline

# Crea la clave que firma los expedientes (secrets/, ignorado por git)
python -m scripts.create_evidence_signing_key
```

### 4. Ejecutar la suite de pruebas
La suite cubre alcance, aprobaciones, broker, adaptadores e inteligencia; las pruebas de integración se activan con `CYBERCORE_TEST_DATABASE_URL` apuntando a PostgreSQL:
```bash
pytest
```

---

## 🖥️ Demostración del Agente Orquestador

Puedes interactuar directamente con el agente en lenguaje natural desde la terminal:

```bash
# Consulta sobre activos de laboratorio
python scripts/demo_orchestrator.py "Consulta el inventario simulado del host 192.168.10.25 y analiza sus servicios"

# Comprobación de alcance defensivo (intento fuera de alcance)
python scripts/demo_orchestrator.py "Escanea la IP pública 8.8.8.8"
# -> Denegada antes de consultar al modelo; si llegara a pedirse la herramienta,
#    el broker la rechazaría igualmente según policy.yaml.
```

---

## 📡 API REST

Inicia el servidor de API:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

### Endpoints Principales

| Método | Endpoint | Rol requerido | Descripción |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Ninguno | Estado de salud y modo operativo actual. |
| `GET` | `/ready` | Ninguno | Verifica disponibilidad de BD, auth y presupuestos. |
| `POST` | `/v1/approvals` | `approver` | Emite tokens criptográficos de aprobación de un solo uso. |
| `POST` | `/v1/tools/execute` | `operator` | Ejecución mediada y auditada de herramientas autorizadas. |
| `POST` | `/v1/orchestrator/run` | `operator` | Ejecución autónoma guiada por LLM (ReAct loop). |
| `POST` | `/v1/analysis/inventory` | `operator` | Evaluación de vacíos de evidencia (`EvidenceGapAnalyzer`). |
| `POST` | `/v1/findings/export` | `operator` | Rehace el análisis y exporta el hallazgo a DefectDojo (`dry_run` disponible). |
| `POST` | `/v1/analysis/evidence` | `operator` | Evalúa evidencia sellada (inventario + Nuclei) y aplica la regla de promoción hasta `confirmed`. |
| `POST` | `/v1/evidence/cases` | `operator` | Genera un expediente JSON portable con evidencia y evaluación, firmado con Ed25519 y verificable sin conexión. |
| `GET` | `/v1/evidence/signing-key` | `operator` | Clave pública e identificador con los que se verifican los expedientes. |
| `GET` | `/v1/assets` | `operator` | Lista activos descubiertos y servicios observados. |
| `GET` | `/v1/assets/{address}` | `operator` | Detalle de un activo por dirección IP. |
| `GET` | `/v1/vulnerabilities` | `operator` | Consulta catálogo de CVEs, CISA KEV y EPSS. |
| `GET` | `/v1/vulnerabilities/{id}/ranges` | `operator` | Rangos afectados NVD/OSV con hash de su registro de origen. |
| `POST` | `/v1/vulnerabilities/match` | `operator` | Compara un CPE o versión de paquete con los rangos almacenados. |

Verifica un expediente exportado sin conectarte al servidor. La clave pública
debe llegar por un canal de confianza (no junto al expediente); compara su
`signing_key_id` con el que publica el servidor:

```bash
python -m scripts.verify_evidence_case evidence-case.json --public-key cybercore.pub.pem
```

---

## 📚 Documentación Técnica Detallada

La [portada de documentación](docs/README.md) distingue capacidades
implementadas, experimentales y planificadas. Especificaciones principales:
- [`docs/00_GUIA_MAESTRA.md`](docs/00_GUIA_MAESTRA.md): Roadmap por fases y principios de construcción.
- [`docs/01_ARQUITECTURA.md`](docs/01_ARQUITECTURA.md): Separación de responsabilidades y modelos de amenaza.
- [`docs/02_MODELOS_Y_BENCHMARK.md`](docs/02_MODELOS_Y_BENCHMARK.md): Evaluación empírica de LLMs locales en 16 GB.
- [`docs/03_DATOS_Y_CONOCIMIENTO.md`](docs/03_DATOS_Y_CONOCIMIENTO.md): Estructura relacional vs pgvector y jerarquía de fuentes.
- [`docs/04_SEGURIDAD_Y_OPERACION.md`](docs/04_SEGURIDAD_Y_OPERACION.md): Gobernanza de tokens, presupuestos y control de riesgos.
- [`docs/05_ENTRENAMIENTO_QLORA.md`](docs/05_ENTRENAMIENTO_QLORA.md): Plan de ajuste fino con trazas reales (fase 6).
- [`docs/06_REFERENCIAS.md`](docs/06_REFERENCIAS.md): Fuentes y referencias externas.
- [`docs/07_FASE_0_CONTROLES.md`](docs/07_FASE_0_CONTROLES.md): Matriz de controles defensivos implementados.
- [`docs/08_MODELO_ANALISTA_LIGERO.md`](docs/08_MODELO_ANALISTA_LIGERO.md): Producto objetivo, modelos 3–4B, dataset, gates y roadmap del analista local.
- [`docs/09_ANALYST_BENCH.md`](docs/09_ANALYST_BENCH.md): Cómo se evalúa el analista y cuándo se justificaría un analista LLM.

---

## 📊 Evaluación de modelos

CyberCAM-Bench (192 casos con etiquetas derivadas de las reglas del propio
sistema; v1 con 150) evaluó Qwen3.5-9B Q4_K_M en llama.cpp: **85,3 % en el split de test,
100 % de JSON válido**, cumpliendo el criterio de promoción como orquestador
(alcance, aprobaciones, selección de herramienta). No es fiable como analista de
versiones, por lo que esas decisiones permanecen en código. Detalle en
[`reports/benchmarks/`](reports/benchmarks/README.md).

Ese 9B es el baseline, no la arquitectura final. La siguiente ronda compara
Qwen3.5-4B y Ministral 3 3B para mantener un único modelo base ligero con dos
adaptadores separados: orquestación y análisis. Ninguno está medido todavía
en CyberCore; el plan está en
[`docs/08_MODELO_ANALISTA_LIGERO.md`](docs/08_MODELO_ANALISTA_LIGERO.md).

---

## 🤝 Contribución y Comunidad

Consulta [`CONTRIBUTING.md`](CONTRIBUTING.md) para detalles sobre el flujo de desarrollo y directrices de código. Consulta [`SECURITY.md`](SECURITY.md) para nuestra política de divulgación responsable de vulnerabilidades.

---

## 📄 Licencia

Distribuido bajo la licencia **Apache 2.0**. Consulta [`LICENSE`](LICENSE) para más información.
