$ErrorActionPreference = "Stop"

$Target = "C:\Users\Computops\Desktop\Proyectos\CyberCore"
$Source = Split-Path -Parent $PSScriptRoot

Write-Host "Destino: $Target"
New-Item -ItemType Directory -Force -Path $Target | Out-Null

if ((Resolve-Path $Source).Path -ne (Resolve-Path $Target -ErrorAction SilentlyContinue).Path) {
    Copy-Item -Path (Join-Path $Source "*") -Destination $Target -Recurse -Force
}

if (-not (Test-Path (Join-Path $Target ".env"))) {
    Copy-Item (Join-Path $Target ".env.example") (Join-Path $Target ".env")
}

Write-Host "CyberCore quedó preparado en $Target" -ForegroundColor Green
Write-Host "Siguiente paso: abre WSL, entra a la carpeta y lee LEEME_PRIMERO.md"
