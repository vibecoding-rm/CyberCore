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
