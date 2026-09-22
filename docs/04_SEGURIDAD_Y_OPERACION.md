# Seguridad y operación

## Reglas no negociables

- Sólo activos propios o autorizados por escrito.
- Denegar por defecto.
- Prohibir shell arbitraria al LLM.
- Separar análisis de ejecución.
- Usar credenciales de sólo lectura cuando sea posible.
- Nunca registrar contraseñas, tokens o datos clínicos.
- Mantener evidencia original y una versión normalizada.
- Toda acción activa tiene timeout, límite y cancelación.
- Registrar actor, objetivo, decisión de política y resultado.

## Secretos

Usa variables de entorno o un gestor de secretos. El archivo `.env` no debe subirse a repositorios ni incluirse en informes. Rota inmediatamente cualquier token que aparezca en logs.

Las claves Bearer de la API deben generarse con `scripts.create_api_credential`,
tener alta entropía y conservarse fuera del repositorio. CyberCore almacena sólo su
hash SHA-256. No envíes estas claves sin TLS fuera de loopback y elimina el hash de
la configuración para revocar una credencial local.

Las aprobaciones usan una identidad `approver` distinta de la identidad `operator`.
El token de aprobación se devuelve una sola vez, no debe registrarse y expira aunque
no se use. Si una ejecución falla después de consumirlo, debe emitirse una nueva
aprobación; nunca se reactiva un token consumido.

## Datos del entorno laboral

Para CAMCEL, el proyecto debe limitarse a infraestructura y términos de TI. No se deben ingerir historias clínicas, estudios, nombres de pacientes, cédulas ni contenido asistencial.

## Respuesta ante un comportamiento inesperado

1. Detener workers/adaptadores.
2. Revocar tokens de APIs.
3. Conservar logs y evidencia.
4. Identificar la solicitud y la decisión de política.
5. Corregir el control determinista.
6. Añadir el caso al benchmark de regresión.
7. No reanudar ejecución activa hasta pasar pruebas.

## Copias

- PostgreSQL: backup diario cifrado.
- Configuración: repositorio privado.
- Evidencia: almacenamiento inmutable o con versionado.
- Retención: definida por política y necesidad, no indefinida por defecto.
