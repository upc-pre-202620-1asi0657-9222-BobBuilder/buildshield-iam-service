package pe.buildshield.iam.infrastructure.messaging;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import pe.buildshield.iam.application.IamCommandService;
import pe.buildshield.iam.domain.model.OrganizationAccess;
import pe.buildshield.iam.domain.model.OrganizationAccess.AccessMode;
import pe.buildshield.iam.shared.messaging.EventEnvelope;
import pe.buildshield.iam.shared.messaging.IdempotentEventProcessor;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Subscription Event Consumer del C4 (pág. 27 de la v4): consume {@code buildshield.subscription} y
 * restringe o reactiva el acceso. {@code SubscriptionExpired} deja la cuenta en solo lectura y
 * {@code SubscriptionActivated} la reactiva, salvo que su estado ya sea de vencida. Los demás tipos de
 * evento se ignoran.
 */
@Component
public class SubscriptionEventConsumer {

    /** Nombre del consumidor en {@code processed_events}. */
    public static final String CONSUMER = "SubscriptionEventConsumer";

    static final String SUBSCRIPTION_ACTIVATED = "SubscriptionActivated";
    static final String SUBSCRIPTION_EXPIRED = "SubscriptionExpired";

    private static final Set<String> EXPIRED_STATUSES = Set.of("EXPIRED", "CANCELED", "CANCELLED", "PAST_DUE");
    private static final Logger log = LoggerFactory.getLogger(SubscriptionEventConsumer.class);

    private final IdempotentEventProcessor processor;
    private final IamCommandService commands;

    public SubscriptionEventConsumer(IdempotentEventProcessor processor, IamCommandService commands) {
        this.processor = processor;
        this.commands = commands;
    }

    @KafkaListener(topics = "${buildshield.messaging.consumes.subscription:buildshield.subscription}")
    public void onMessage(ConsumerRecord<String, String> record) {
        processor.process(CONSUMER, record, this::handle);
    }

    void handle(EventEnvelope event) {
        switch (event.eventType()) {
            case SUBSCRIPTION_ACTIVATED, SUBSCRIPTION_EXPIRED -> {
                JsonNode payload = event.payload();
                UUID organizationId = payload.hasNonNull("organizationId")
                        ? UUID.fromString(payload.get("organizationId").asText()) : event.organizationId();
                AccessMode mode = SUBSCRIPTION_EXPIRED.equals(event.eventType())
                        || EXPIRED_STATUSES.contains(payload.path("status").asText("").trim().toUpperCase(Locale.ROOT))
                        ? AccessMode.READ_ONLY : AccessMode.FULL;
                commands.applySubscriptionStatus(new OrganizationAccess(organizationId, mode));
                log.info("Acceso de la organización {} actualizado a {}", organizationId, mode);
            }
            default -> log.debug("Evento {} ignorado por iam", event.eventType());
        }
    }
}
