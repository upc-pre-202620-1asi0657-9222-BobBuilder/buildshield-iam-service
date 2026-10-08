# buildshield-iam-service

Identidad y Acceso de BuildShield (BobBuilder): registro de organizaciones, sesiones JWT RS256 y usuarios.
Contrato de la arquitectura: `wiki/informe-tf/plan-microservicios.md` del proyecto.

| Dato | Valor |
|---|---|
| Puerto | 8081 |
| Base | `iam_db` (PostgreSQL 16+) |
| Paquete | `pe.buildshield.iam` |
| Publica | `buildshield.iam`: `OrganizationRegistered`, `UserCreated`, `UserUpdated` |
| Consume | `buildshield.subscription`: `SubscriptionActivated`, `SubscriptionExpired` (tabla `organization_access`) |

## Endpoints

- `POST /api/v1/auth/sign-up`, `sign-in`, `refresh`, `sign-out`, `password-reset`, `password-reset/confirm`
- `POST /api/v1/users`, `GET /api/v1/users`, `PATCH /api/v1/users/{id}` (solo ADMINISTRATOR)
- OpenAPI en `/api/v1/api-docs` y `/swagger-ui.html` (perfiles local y test)

## Variables de entorno

`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `KAFKA_BOOTSTRAP_SERVERS` (por defecto `localhost:9092`),
`BUILDSHIELD_JWT_PUBLIC_KEY`, `BUILDSHIELD_JWT_PRIVATE_KEY` y `BUILDSHIELD_PASSWORD_RESET_URL`. Perfiles `local`,
`test` y `prod`.

## Ejecutar en local (clúster PostgreSQL 127.0.0.1:5433 con autenticación trust)

```bash
mvn -B package -DskipTests
BUILDSHIELD_JWT_PRIVATE_KEY="$(cat ~/.buildshield/jwt-private.pem)" \
BUILDSHIELD_JWT_PUBLIC_KEY="$(cat ~/.buildshield/jwt-public.pem)" \
java -jar target/buildshield-iam-service-0.1.0-SNAPSHOT.jar --spring.profiles.active=local
```

## Pruebas

```bash
mvn -B verify -Dbuildshield.test.external-database=true
```

Las `*IT` usan la base temporal `iam_it` en `127.0.0.1:5433` con el usuario `buildshield_core` (se cambian con
`-Dbuildshield.test.iam-url=...` y `-Dbuildshield.test.database-user=...`) y Kafka embebido (`@EmbeddedKafka`).
Sin la propiedad usan Testcontainers (requiere Docker). JaCoCo exige 80 % de líneas en `domain` y `application`.
