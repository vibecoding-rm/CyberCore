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
- Aprobaciones: operador, aprobador, herramienta, argumentos canónicos, hash del
  token, expiración y solicitud que lo consumió.
- Auditoría de solicitudes, decisiones, resultados y evidencia.

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

## Implementado: NVD y OSV

```bash
# CVE concretos
python -m scripts.ingest_vulnerabilities --nvd --osv --cve CVE-2024-6387
# Los KEV ya almacenados (NVD sin clave: ~6 s por CVE; define NVD_API_KEY para 10x)
python -m scripts.ingest_vulnerabilities --nvd --osv --limit 50
```

- Cada respuesta original de NVD/OSV se guarda íntegra en `intel_source_records`
  con su SHA-256, URL y fecha. Cada rango en `vulnerability_affected_ranges`
  apunta al registro del que procede.
- NVD aporta CVSS (se prefiere la métrica `Primary` más reciente), CWE y rangos
  CPE. Las configuraciones `AND` (producto sobre una plataforma concreta) se
  marcan `requires_platform` y nunca producen `affected` por sí solas.
- OSV aporta rangos por paquete (`SEMVER`/`ECOSYSTEM`) y los alias del CVE
  (GHSA, Debian, etc.). Los rangos `GIT` se descartan porque son commits.
- La comparación de versiones es conservadora: `9.6p1 < 9.8` se decide, pero
  `9.8p1` frente a `<= 9.8`, pre-releases o epochs de Debian devuelven
  `indeterminate`. Los rangos `ECOSYSTEM` quedan `indeterminate` hasta tener
  comparadores específicos por ecosistema.
- El análisis de inventario usa el CPE que reporta Nmap. Coincidencia por
  `vendor:product` exacto, nunca por texto aproximado.
- Resultado dentro de rango con inventario real ⇒ `probable`, nunca `confirmed`:
  los backports de distribución y la validación independiente siguen pendientes.

