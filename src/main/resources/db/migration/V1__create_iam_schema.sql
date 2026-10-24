-- Identidad y Acceso (iam_db). Portado de V4 del Core (iam.users, refresh_tokens,
-- password_reset_tokens, revoked_access_tokens), ahora en el esquema public de su propia base.

CREATE TABLE users (
    id              UUID PRIMARY KEY,
    organization_id UUID         NOT NULL,
    email           VARCHAR(254) NOT NULL,
    full_name       VARCHAR(150) NOT NULL,
    role            VARCHAR(30)  NOT NULL,
    password_hash   VARCHAR(100) NOT NULL,
    active          BOOLEAN      NOT NULL,
    version         BIGINT       NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL,
    created_by      UUID         NOT NULL,
    updated_at      TIMESTAMPTZ  NOT NULL,
    updated_by      UUID         NOT NULL,
    -- El correo identifica al usuario al iniciar sesión: único entre todas las organizaciones.
    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT ck_users_role CHECK (role IN ('ADMINISTRATOR', 'WAREHOUSE_MANAGER', 'SITE_MANAGER'))
);

CREATE INDEX idx_users_organization ON users (organization_id);

-- Tokens de renovación: solo se guarda el hash SHA-256 del valor entregado al cliente.
CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY,
    user_id         UUID        NOT NULL REFERENCES users (id),
    organization_id UUID        NOT NULL,
    token_hash      VARCHAR(64) NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID,
    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash)
);

CREATE INDEX idx_refresh_tokens_active_user ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- Enlaces de recuperación de contraseña: vencen y se usan una vez.
CREATE TABLE password_reset_tokens (
    id              UUID PRIMARY KEY,
    user_id         UUID        NOT NULL REFERENCES users (id),
    organization_id UUID        NOT NULL,
    token_hash      VARCHAR(64) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    CONSTRAINT uk_password_reset_tokens_hash UNIQUE (token_hash)
);

-- Tokens de acceso revocados por cierre de sesión, hasta que venzan.
CREATE TABLE revoked_access_tokens (
    jti        VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_revoked_access_tokens_expires ON revoked_access_tokens (expires_at);

-- RUC registrados: un RUC pertenece a una sola organización. Los datos de la organización viven en
-- Organización y Configuración (organization_db), que los recibe con OrganizationRegistered.
CREATE TABLE registered_rucs (
    ruc             VARCHAR(11) NOT NULL,
    organization_id UUID        NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL,
    CONSTRAINT uk_registered_rucs_ruc PRIMARY KEY (ruc),
    CONSTRAINT uk_registered_rucs_organization UNIQUE (organization_id),
    CONSTRAINT ck_registered_rucs_digits CHECK (ruc ~ '^[0-9]{11}$')
);

-- Estado de la suscripción de cada organización (copia alimentada por SubscriptionActivated y
-- SubscriptionExpired). EXPIRED deja la cuenta en solo lectura.
CREATE TABLE organization_access (
    organization_id UUID PRIMARY KEY,
    plan            VARCHAR(20) NOT NULL,
    status          VARCHAR(20) NOT NULL,
    valid_until     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_organization_access_status CHECK (status IN ('TRIAL', 'ACTIVE', 'EXPIRED'))
);

-- Transactional Outbox (kernel compartido): eventos escritos en la misma transacción que el cambio de
-- negocio; OutboxPublisher los envía a Kafka y marca published_at.
CREATE TABLE outbox_events (
    id              UUID PRIMARY KEY,
    event_type      VARCHAR(100) NOT NULL,
    aggregate_type  VARCHAR(50)  NOT NULL,
    aggregate_id    VARCHAR(100) NOT NULL,
    organization_id UUID         NOT NULL,
    actor_id        UUID,
    correlation_id  VARCHAR(64),
    payload         JSONB        NOT NULL,
    occurred_at     TIMESTAMPTZ  NOT NULL,
    published_at    TIMESTAMPTZ
);

CREATE INDEX idx_outbox_events_pending ON outbox_events (occurred_at, id) WHERE published_at IS NULL;

-- Consumidor idempotente (kernel compartido): un evento se procesa una sola vez.
CREATE TABLE processed_events (
    event_id     UUID PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL
);
