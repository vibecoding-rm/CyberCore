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
- Límite horario y concurrencia máxima aplicados por el broker.
- Errores internos de adaptadores ocultos al cliente y registrados en el proceso.
- Evidencia emitida sólo cuando la ejecución termina correctamente y su contenido
  admite representación JSON canónica.
- Solicitudes, decisiones, argumentos originales y normalizados, estados, errores y
  evidencia persistidos en PostgreSQL. La evidencia y el estado terminal se guardan
  en una única transacción.
- Ejecución cerrada por defecto ante fallos de auditoría: el adaptador no comienza
  si no puede crearse el registro durable y la respuesta no expone evidencia si no
  puede cerrarse ese registro.
- Endpoint `GET /ready` ligado a la disponibilidad del almacén de auditoría.
- Tokens libres de aprobación rechazados. Sin un verificador explícito, ninguna
  herramienta que requiera aprobación puede ejecutarse.

La serialización es canónica para los tipos admitidos por CyberCore, pero no se
declara como implementación completa de RFC 8785.

## Controles que sólo valen en un proceso local

Los siguientes controles son adecuados para el MVP local con un único proceso,
pero no coordinan varios workers, contenedores o nodos:

- El límite de solicitudes usa una ventana temporal en memoria.
- El límite de concurrencia usa un semáforo del proceso.
- El detalle técnico de excepciones depende del logging local y no está centralizado;
  el estado y el error público de la solicitud sí quedan en la auditoría durable.
- La política se carga desde un archivo local sin firma ni control de integridad.
- La auditoría se persiste en PostgreSQL, pero todavía no tiene permisos separados,
  retención inmutable ni encadenamiento criptográfico contra alteraciones directas.
- No existe todavía un almacén compartido de aprobaciones, usos únicos o protección
  contra replay. Por eso las acciones que requieren aprobación permanecen cerradas.
- La API no tiene todavía autenticación, RBAC ni identidad verificable; el campo
  `requested_by` es informativo y no confiable.
- El contador horario se reinicia al reiniciar el proceso.

No se debe ejecutar más de un worker ni exponer la API fuera de loopback basándose
en estos controles locales.

## Condiciones antes de habilitar un adaptador real

1. Autenticación y autorización verificables.
2. Aprobaciones durables, ligadas al hash de argumentos canónicos, con expiración y
   consumo único atómico.
3. Presupuestos y concurrencia compartidos entre procesos.
4. Endurecimiento del registro durable con roles mínimos, retención inmutable y
   protección verificable contra alteraciones directas.
5. Política firmada o protegida contra modificaciones no autorizadas.
6. Pruebas específicas del adaptador, incluyendo timeout, cancelación y límites.
7. Revisión explícita de alcance por el propietario de los activos.
