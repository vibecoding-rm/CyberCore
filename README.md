# CyberCore

<p align="center">
  <strong>Plataforma Autónoma de Análisis Defensivo y Gestión de Vulnerabilidades</strong><br>
  <em>Gobernanza estricta de alcance, mediación criptográfica de herramientas y evidencia auditable.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue?logo=python" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/PostgreSQL-16%20%2B%20pgvector-336791?logo=postgresql" alt="PostgreSQL 16">
  <img src="https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Ollama-Local%20Inference-black?logo=ollama" alt="Ollama">
  <img src="https://img.shields.io/badge/Tests-174%20Passing-brightgreen?logo=pytest" alt="Tests">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="License">
</p>

---

## 🛡️ ¿Qué es CyberCore?

**CyberCore** no es una "IA que hackea". Es un analista defensivo local diseñado para operar en infraestructura propia o con autorización estricta. Resuelve el principal problema de los agentes de seguridad: **la falta de control, la alucinación de vulnerabilidades y la ejecución arbitraria de comandos**.

En CyberCore:
1. **La evidencia decide; el modelo explica y organiza.**
2. **Ningún LLM tiene acceso directo a una shell.** Toda interacción ocurre mediante contratos tipados y estrictamente validados en [ToolBroker](app/core/tool_broker.py).
3. **El alcance es inmutable:** [PolicyEngine](app/core/policy.py) rechaza de forma determinista cualquier IP pública o red fuera de los CIDRs autorizados.
4. **Trazabilidad criptográfica total:** Cada solicitud, decisión de política, resultado de herramienta y reporte final se sella con hashes **SHA-256** en PostgreSQL.
5. **Aprobaciones de un solo uso:** Las acciones de riesgo medio o alto requieren tokens emitidos por un supervisor y consumidos atómicamente.

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
│            CyberCore Autonomous Orchestrator (ReAct)             │
│            (Qwen 3.5 9B / Modelos locales con Ollama)            │
│               - Planificación paso a paso estructurada           │
│               - Selección de herramientas autorizadas            │
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
│   └── get_mock_inventory  -> Entorno sintético de laboratorio    │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Evidencia cruda + SHA-256
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│             Persistencia e Inteligencia (PostgreSQL)             │
│   ├── assets & services   -> Inventario observable actualizado   │
│   ├── vulnerabilities     -> KEV + EPSS + NVD/OSV (rangos)      │
│   └── evidence & findings -> Evaluación con EvidenceGapAnalyzer  │
└──────────────────────────────────────────────────────────────────┘
```

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
Inicia PostgreSQL (con extensión `pgvector`) y Ollama:
```bash
docker compose up -d postgres ollama
```

Para descargar el modelo orquestador local:
```bash
docker compose exec ollama ollama pull qwen3.5:9b
```

### 3. Migrar la base de datos y sembrar inteligencia base
```bash
# Aplica las migraciones DDL
python scripts/migrate_db.py

# Siembra el catálogo base de vulnerabilidades KEV y EPSS
python scripts/ingest_vulnerabilities.py --baseline
```

### 4. Ejecutar la suite de pruebas
CyberCore cuenta con **174 pruebas automatizadas** (más 18 de integración con PostgreSQL) que garantizan el control de alcance, aprobaciones y persistencia:
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
# -> El orquestador denegará la acción automáticamente respetando policy.yaml.
```

---

## 📡 API REST

Inicia el servidor de API:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
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
| `GET` | `/v1/assets` | `operator` | Lista activos descubiertos y servicios observados. |
| `GET` | `/v1/assets/{address}` | `operator` | Detalle de un activo por dirección IP. |
| `GET` | `/v1/vulnerabilities` | `operator` | Consulta catálogo de CVEs, CISA KEV y EPSS. |
| `GET` | `/v1/vulnerabilities/{id}/ranges` | `operator` | Rangos afectados NVD/OSV con hash de su registro de origen. |
| `POST` | `/v1/vulnerabilities/match` | `operator` | Compara un CPE o versión de paquete con los rangos almacenados. |

---

## 📚 Documentación Técnica Detallada

La carpeta [`docs/`](docs/) contiene las especificaciones maestras de diseño:
- [`docs/00_GUIA_MAESTRA.md`](docs/00_GUIA_MAESTRA.md): Roadmap por fases y principios de construcción.
- [`docs/01_ARQUITECTURA.md`](docs/01_ARQUITECTURA.md): Separación de responsabilidades y modelos de amenaza.
- [`docs/02_MODELOS_Y_BENCHMARK.md`](docs/02_MODELOS_Y_BENCHMARK.md): Evaluación empírica de LLMs locales en 16 GB.
- [`docs/03_DATOS_Y_CONOCIMIENTO.md`](docs/03_DATOS_Y_CONOCIMIENTO.md): Estructura relacional vs pgvector y jerarquía de fuentes.
- [`docs/04_SEGURIDAD_Y_OPERACION.md`](docs/04_SEGURIDAD_Y_OPERACION.md): Gobernanza de tokens, presupuestos y control de riesgos.
- [`docs/07_FASE_0_CONTROLES.md`](docs/07_FASE_0_CONTROLES.md): Matriz de controles defensivos implementados.

---

## 🤝 Contribución y Comunidad

Consulta [`CONTRIBUTING.md`](CONTRIBUTING.md) para detalles sobre el flujo de desarrollo y directrices de código. Consulta [`SECURITY.md`](SECURITY.md) para nuestra política de divulgación responsable de vulnerabilidades.

---

## 📄 Licencia

Distribuido bajo la licencia **Apache 2.0**. Consulta [`LICENSE`](LICENSE) para más información.
