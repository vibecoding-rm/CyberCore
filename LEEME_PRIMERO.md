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
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
   ```

5. Abre `http://127.0.0.1:8080/docs`.

## Primera prueba segura

```bash
curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/v1/tools/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"192.168.10.25"},"requested_by":"maikel"}'
```

Prueba de bloqueo:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/tools/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"8.8.8.8"},"requested_by":"maikel"}'
```

La segunda solicitud debe ser rechazada porque `8.8.8.8` no está dentro de las redes privadas autorizadas.

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
