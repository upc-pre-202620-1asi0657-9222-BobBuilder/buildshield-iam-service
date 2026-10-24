# Desviaciones frente a la arquitectura v4

Fuente fija: `buildshield-presentacion-v4.pdf`. El ER de `iam_db` está en la pág. 15 y el C4 de componentes de Identidad y Acceso, en la pág. 27. Este archivo lista lo que el servicio tiene y la v4 no dibuja, con su motivo, para que se agregue al ER o al C4 del informe.

## Tablas fuera del ER

| Tabla | Motivo |
|---|---|
| `registered_rucs` | Valida que el RUC sea único al registrarse (US01) en la misma transacción que crea al administrador. Sin ella, el RUC repetido solo se detectaría después, en Organización y Configuración, y el usuario ya habría quedado creado. |
| `revoked_access_tokens` | Lista de tokens de acceso cerrados con sign-out, guardados hasta que vencen (15 min). Fuera de iam el token sigue valiendo hasta que vence. |

## Columnas fuera del ER

| Tabla | Columnas | Motivo |
|---|---|---|
| `users` | `version`, `created_at`, `created_by`, `updated_at`, `updated_by` | Bloqueo optimista y auditoría JPA del kernel. |
| `refresh_tokens` | `organization_id`, `issued_at`, `replaced_by` | Rotación del token de renovación: cada uso emite uno nuevo y deja el anterior enlazado. |
| `password_reset_tokens` | `organization_id` | Permite filtrar por organización sin consultar `users`. |
| `outbox_events` | `correlation_id` | Cabecera Kafka `X-Correlation-Id` para seguir una petición entre servicios. |

`users.phone` se recibe al crear (`POST /users`), se cambia con `PATCH /users/{id}` y se devuelve en todas las vistas de usuario.

## Componentes

- **IAM Controller** está partido en `AuthController` (autenticación y recuperación) y `UsersController` (usuarios y roles), en el mismo paquete `interfaces.rest`.
- **IAM Repository** son los repositorios por agregado: `UserRepository`, los de tokens y `OrganizationAccessRepository`.
- **IAM Domain**: `Role` es un enum y cada rol trae sus `Permission` (enum, sin tabla), sacados de las responsabilidades de cada persona en el C4 de contenedores (pág. 21). `GET /users/me` los devuelve para la web. Cada servicio sigue validando el rol con `@PreAuthorize`. `Session` es `RefreshToken`.

## Contrato con otros servicios

- iam ya no envía correos. Publica `PasswordResetRequested` (`userId`, `email`, `fullName`, `resetLink`, `expiresAt`) en `buildshield.iam`, y Notificaciones lo envía por SendGrid. `resetLink` es una credencial: no debe guardarse en logs ni en la bitácora de auditoría.
- `outbox_events.payload` guarda el sobre completo del evento (`eventId`, `eventType`, `occurredAt`, `organizationId`, `aggregateType`, `aggregateId`, `actorId`, `version`, `payload`), porque el ER no tiene `aggregate_type` ni `actor_id`. Lo que llega a Kafka no cambia.
