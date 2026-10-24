-- Alineación con el diagrama entidad relación de la presentación v4 (pág. 15, iam_db), que es la fuente
-- fija desde el 2026-10-22. Las columnas que no están en el ER y se conservan están en DESVIACIONES.md.

-- users: largos del ER y teléfono opcional.
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(120);
ALTER TABLE users ALTER COLUMN full_name TYPE VARCHAR(120);
ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(20);
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);
ALTER TABLE users ADD COLUMN phone VARCHAR(20);

-- Hash SHA-256 en hexadecimal: siempre 64 caracteres.
ALTER TABLE refresh_tokens ALTER COLUMN token_hash TYPE CHAR(64);
ALTER TABLE password_reset_tokens ALTER COLUMN token_hash TYPE CHAR(64);

-- organization_access: solo el modo de acceso (FULL o READ_ONLY), como en el ER.
ALTER TABLE organization_access ADD COLUMN access_mode VARCHAR(15);
UPDATE organization_access SET access_mode = CASE WHEN status = 'EXPIRED' THEN 'READ_ONLY' ELSE 'FULL' END;
ALTER TABLE organization_access ALTER COLUMN access_mode SET NOT NULL;
ALTER TABLE organization_access DROP CONSTRAINT ck_organization_access_status;
ALTER TABLE organization_access DROP COLUMN plan;
ALTER TABLE organization_access DROP COLUMN status;
ALTER TABLE organization_access DROP COLUMN valid_until;
ALTER TABLE organization_access ADD CONSTRAINT ck_organization_access_mode CHECK (access_mode IN ('FULL', 'READ_ONLY'));

-- outbox_events: columnas del ER. El sobre completo del evento (con aggregateType y actorId) va en payload.
-- correlation_id se conserva para la cabecera Kafka de trazabilidad.
UPDATE outbox_events SET payload = jsonb_build_object(
        'eventId', id, 'eventType', event_type,
        'occurredAt', to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'organizationId', organization_id, 'aggregateType', aggregate_type, 'aggregateId', aggregate_id,
        'actorId', actor_id, 'version', 1, 'payload', payload);
ALTER TABLE outbox_events DROP COLUMN aggregate_type;
ALTER TABLE outbox_events DROP COLUMN actor_id;
ALTER TABLE outbox_events ALTER COLUMN aggregate_id TYPE UUID USING aggregate_id::uuid;
ALTER TABLE outbox_events ALTER COLUMN event_type TYPE VARCHAR(60);

-- processed_events: un mismo evento puede procesarlo más de un consumidor del servicio.
ALTER TABLE processed_events ADD COLUMN consumer VARCHAR(60);
UPDATE processed_events SET consumer = 'SubscriptionEventConsumer';
ALTER TABLE processed_events ALTER COLUMN consumer SET NOT NULL;
ALTER TABLE processed_events DROP CONSTRAINT processed_events_pkey;
ALTER TABLE processed_events ADD PRIMARY KEY (event_id, consumer);
