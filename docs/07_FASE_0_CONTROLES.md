# Fase 0 — controles implementados y límites locales

## Estado

CyberCore permanece en modo exclusivamente simulado. El único adaptador cargado es
`get_mock_inventory`; Nmap, Nuclei, Wazuh, Greenbone y cualquier otro adaptador real
continúan deshabilitados.

Cambiar una variable de entorno no basta para activar ejecución real. Durante esta
fase, `TOOL_MODE` sólo acepta `mock` y el broker rechaza al arrancar cualquier
adaptador cuyo modo no sea `mock`.

## Controles ejecutables

- Configuración YAML validada de forma estricta al arrancar.
- Alcance reducido a loopback y `192.168.10.0/24`, reservado para el laboratorio.
- Nombres DNS denegados, incluso si se cambia `allow_hostnames`, hasta implementar
  resolución y revalidación seguras.
- Comparación separada de IPv4 e IPv6; una familia no autorizada se rechaza sin
  provocar excepciones.
- Límite de direcciones por solicitud aplicado a objetivos CIDR.
- Esquema estricto por adaptador; los campos extra y tipos implícitos se rechazan.
- Argumentos normalizados antes de política, aprobación y ejecución.
- Serialización determinista: claves ordenadas, JSON compacto, UTF-8, Unicode NFC,
  cero normalizado y rechazo de números no finitos, tipos no JSON y colisiones de
  claves tras normalización.
- Timeout limitado por el adaptador y por la política global.
- Límite horario compartido entre workers mediante reservas serializadas en
  PostgreSQL, con ventana basada en el reloj de la base de datos.
- Concurrencia máxima compartida mediante leases durables y serializados. Los
  leases vencen después del timeout de la herramienta más un margen de gracia, por
  lo que la caída de un worker no bloquea capacidad indefinidamente.
- `request_id` reservado una sola vez para rechazar replays sin sobrescribir la
  auditoría original.
- Errores internos de adaptadores ocultos al cliente y registrados en el proceso.
- Evidencia emitida sólo cuando la ejecución termina correctamente y su contenido
  admite representación JSON canónica.
- Solicitudes, decisiones, argumentos originales y normalizados, estados, errores y
  evidencia persistidos en PostgreSQL. La evidencia y el estado terminal se guardan
  en una única transacción.
- Ejecución cerrada por defecto ante fallos de auditoría: el adaptador no comienza
  si no puede crearse el registro durable y la respuesta no expone evidencia si no
  puede cerrarse ese registro.
- Endpoint `GET /ready` ligado a la disponibilidad de auditoría, autenticación,
  aprobaciones y coordinación de presupuestos.
- Autenticación Bearer con claves de alta entropía conservadas únicamente como
  hashes SHA-256 en configuración, comparación constante y cierre por defecto si no
  hay credenciales.
- Roles `viewer`, `operator` y `approver`; sólo `operator` puede solicitar
  herramientas y sólo `approver` puede emitir una aprobación para otro sujeto. La
  identidad auditada se deriva de la credencial y `requested_by` no forma parte del
  cuerpo público de ejecución.
- Aprobaciones persistidas en PostgreSQL con el hash del token, operador, aprobador,
  herramienta, argumentos normalizados, hash canónico y expiración basada en el
  reloj de la base de datos.
- Consumo único mediante actualización condicional atómica. Replay, expiración o
  cambios de operador, herramienta o argumentos se rechazan con la misma respuesta.
- Tokens libres de aprobación rechazados; el texto del token nunca se persiste.

La serialización es canónica para los tipos admitidos por CyberCore, pero no se
declara como implementación completa de RFC 8785.

## Límites operativos pendientes

Los presupuestos ya coordinan varios workers que comparten PostgreSQL. Persisten
los siguientes límites del MVP:

- El detalle técnico de excepciones depende del logging local y no está centralizado;
  el estado y el error público de la solicitud sí quedan en la auditoría durable.
- La política se carga desde un archivo local sin firma ni control de integridad.
- La auditoría se persiste en PostgreSQL, pero todavía no tiene permisos separados,
  retención inmutable ni encadenamiento criptográfico contra alteraciones directas.
- El token se consume antes de abrir la ejecución en el journal. Si la auditoría no
  puede iniciarse, no se ejecuta el adaptador y el token permanece consumido por
  seguridad; el aprobador debe emitir uno nuevo.
- Las credenciales se configuran localmente: todavía no existen rotación coordinada,
  revocación durable, rate limiting por identidad ni integración con un proveedor
  OIDC. La API no debe exponerse sin TLS en un despliegue remoto.

La API no debe exponerse fuera de loopback basándose sólo en estos controles: aún
faltan TLS y el ciclo de vida de credenciales para un despliegue remoto.

## Condiciones antes de habilitar un adaptador real

1. Ciclo de vida de credenciales para despliegue: TLS, rotación y revocación durable
   o integración con un proveedor de identidad.
2. Procedimiento operativo que asigne aprobadores independientes y revise la
   vigencia de sus credenciales.
3. Endurecimiento del registro durable con roles mínimos, retención inmutable y
   protección verificable contra alteraciones directas.
4. Política firmada o protegida contra modificaciones no autorizadas.
5. Pruebas específicas del adaptador, incluyendo timeout, cancelación y límites.
6. Revisión explícita de alcance por el propietario de los activos.
