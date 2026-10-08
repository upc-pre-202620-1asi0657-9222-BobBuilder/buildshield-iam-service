/**
 * Eventos de integración entre microservicios: sobre JSON común ({@link pe.buildshield.iam.shared.messaging.EventEnvelope}),
 * Transactional Outbox ({@link pe.buildshield.iam.shared.messaging.OutboxWriter} y
 * {@link pe.buildshield.iam.shared.messaging.OutboxPublisher}) y consumo idempotente
 * ({@link pe.buildshield.iam.shared.messaging.IdempotentEventProcessor}). Entrega al menos una vez.
 */
package pe.buildshield.iam.shared.messaging;
