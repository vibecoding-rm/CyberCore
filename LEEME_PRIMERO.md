# CyberCore Starter v1

Paquete inicial para construir un analista defensivo local de vulnerabilidades con evidencia, alcance controlado y aprobación humana.

## Qué contiene

- Guía técnica y hoja de ruta.
- API mínima con FastAPI.
- Motor de políticas de alcance.
- Broker de herramientas sin shell libre.
- Adaptador simulado de inventario para probar el flujo sin tocar una red.
- PostgreSQL y esquema inicial.
- Configuración para Ollama, con los modelos desacoplados de la lógica.
- Casos iniciales de CyberCAM-Bench.
- Pruebas automáticas.
- Script de instalación para Windows/WSL.

## Regla principal

No conectes todavía Nmap, Nuclei, Greenbone o Wazuh a una red real. Primero ejecuta las pruebas en modo `mock`, comprueba el motor de políticas y define por escrito los activos autorizados.

## Instalación rápida en tu PC

1. Descomprime la carpeta `CyberCore` dentro de:

   `C:\Users\Computops\Desktop\Proyectos`

2. Abre PowerShell como usuario normal.
3. Ejecuta:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\scripts\instalar_windows.ps1
   ```

4. En WSL/Ubuntu, entra al proyecto y ejecuta:

   ```bash
   cp .env.example .env
   docker compose up -d postgres ollama
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   python3 -m scripts.create_api_credential local-operator
   # Guarda la clave y copia en .env la línea API_CREDENTIALS_JSON mostrada.
   python3 -m scripts.migrate_db
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
   ```

5. Abre `http://127.0.0.1:8080/docs`.

## Primera prueba segura

```bash
export CYBERCORE_API_KEY='<clave mostrada al crear la credencial>'
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/ready
curl -s -X POST http://127.0.0.1:8080/v1/tools/execute \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${CYBERCORE_API_KEY}" \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"192.168.10.25"}}'
```

Prueba de bloqueo:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/tools/execute \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${CYBERCORE_API_KEY}" \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"8.8.8.8"}}'
```

La segunda solicitud debe ser rechazada porque `8.8.8.8` no está dentro de las redes privadas autorizadas.
Tanto la ejecución permitida como la solicitud rechazada quedan registradas en
PostgreSQL. Si el registro durable no está disponible, el adaptador no se ejecuta.
La identidad registrada se obtiene de la credencial; el cliente no puede enviar ni
suplantar `requested_by`.

Antes de habilitar una herramienta que requiera aprobación, configura además una
credencial separada con `--role approver`. Los objetos generados para `operator` y
`approver` deben convivir dentro de la misma lista `API_CREDENTIALS_JSON`. El
aprobador usa `POST /v1/approvals`; la clave devuelta se muestra una sola vez y sólo
sirve para el operador, herramienta y argumentos exactos autorizados.

## Orden recomendado

1. Ejecutar el modo simulado y sus pruebas.
2. Personalizar `config/policy.yaml`.
3. Probar modelos por separado, sin darles herramientas.
4. Ejecutar CyberCAM-Bench.
5. Conectar Nmap con un adaptador de sólo descubrimiento.
6. Agregar Nuclei con plantillas permitidas y aprobación.
7. Integrar fuentes CVE/KEV/EPSS/OSV.
8. Incorporar Wazuh, Greenbone y DefectDojo en fases posteriores.

Lee `docs/00_GUIA_MAESTRA.md` antes de cambiar el modo de ejecución.
