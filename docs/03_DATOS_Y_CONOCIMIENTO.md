# Datos y conocimiento

## Qué va en PostgreSQL

- Activos, direcciones e identidad.
- Servicios y software observado.
- Escaneos y ejecuciones.
- Evidencia y hashes.
- Vulnerabilidades y rangos de versiones.
- CVSS, EPSS, KEV.
- Findings y estados.
- Relaciones entre activos.
- Aprobaciones y auditoría.

## Qué va en pgvector

- Advisories técnicos.
- Documentación de remediación.
- Notas internas autorizadas.
- Informes anteriores sanitizados.
- Fragmentos con procedencia y fecha.

## Jerarquía de fuentes

1. Advisory del proveedor.
2. CISA, NVD, OSV y MITRE según el dato.
3. Documentación del proyecto/herramienta.
4. Investigación comunitaria reconocida.
5. Blogs, chats o material experimental.

Cuando dos fuentes discrepan, conserva ambas, marca el conflicto y evita una conclusión automática.

## Actualización

- EPSS: diaria.
- CISA KEV: diaria.
- OSV/advisories: diaria o bajo demanda.
- NVD: incremental.
- ATT&CK/CWE/CAPEC: por versión publicada.
- Nuclei templates: actualización controlada, con revisión y hash.

No entrenes estos datos cambiantes dentro del modelo.
