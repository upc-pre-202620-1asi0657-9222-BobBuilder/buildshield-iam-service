package pe.buildshield.iam.infrastructure.messaging;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import pe.buildshield.iam.application.IamCommandService;
import pe.buildshield.iam.domain.model.OrganizationAccess;
import pe.buildshield.iam.shared.messaging.EventEnvelope;
import pe.buildshield.iam.shared.messaging.IdempotentEventProcessor;

import java.time.Instant;
import java.util.UUID;

/**
 * Consume el tópico {@code buildshield.subscription}: {@code SubscriptionActivated} y
 * {@code SubscriptionExpired} actualizan {@code organization_access} (con la suscripción vencida, la
 * cuenta queda en solo lectura). Los demás tipos de evento se ignoran.
 */
@Component
public class SubscriptionEventConsumer {

    static final String SUBSCRIPTION_ACTIVATED = "SubscriptionActivated";
    static final String SUBSCRIPTION_EXPIRED = "SubscriptionExpired";

    private static final Logger log = LoggerFactory.getLogger(SubscriptionEventConsumer.class);

    private final IdempotentEventProcessor processor;
    private final IamCommandService commands;

    public SubscriptionEventConsumer(IdempotentEventProcessor processor, IamCommandService commands) {
        this.processor = processor;
        this.commands = commands;
    }

    @KafkaListener(topics = "${buildshield.messaging.consumes.subscription:buildshield.subscription}")
    public void onMessage(ConsumerRecord<String, String> record) {
        processor.process(record, this::handle);
    }

    void handle(EventEnvelope event) {
        switch (event.eventType()) {
            case SUBSCRIPTION_ACTIVATED, SUBSCRIPTION_EXPIRED -> {
                JsonNode payload = event.payload();
                UUID organizationId = payload.hasNonNull("organizationId")
                        ? UUID.fromString(payload.get("organizationId").asText()) : event.organizationId();
                OrganizationAccess.Status status = SUBSCRIPTION_EXPIRED.equals(event.eventType())
                        ? OrganizationAccess.Status.EXPIRED
                        : OrganizationAccess.Status.parse(payload.path("status").asText(null));
                Instant validUntil = payload.hasNonNull("validUntil") ? instant(payload.get("validUntil").asText()) : null;
                commands.applySubscriptionStatus(new OrganizationAccess(organizationId,
                        payload.path("plan").asText(null), status, validUntil));
                log.info("Acceso de la organización {} actualizado a {}", organizationId, status);
            }
            default -> log.debug("Evento {} ignorado por iam", event.eventType());
        }
    }

    /** Acepta un instante ISO-8601 o una fecha (fin del día UTC). */
    static Instant instant(String value) {
        try {
            return Instant.parse(value);
        } catch (java.time.format.DateTimeParseException notAnInstant) {
            return java.time.LocalDate.parse(value).plusDays(1).atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
        }
    }
}
