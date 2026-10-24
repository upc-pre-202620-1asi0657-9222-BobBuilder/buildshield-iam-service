package pe.buildshield.iam.infrastructure.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import pe.buildshield.iam.shared.config.BuildshieldProperties;
import pe.buildshield.iam.shared.messaging.OutboxPublisher;

import java.time.Clock;

/**
 * Productor Kafka de iam: cada 500 ms envía al tópico {@code buildshield.iam} los eventos pendientes del
 * outbox ({@code OrganizationRegistered}, {@code UserCreated}, {@code UserUpdated}).
 */
@Component
public class IamOutboxPublisher extends OutboxPublisher {

    public IamOutboxPublisher(JdbcTemplate jdbc, KafkaTemplate<String, String> kafka, ObjectMapper json,
            PlatformTransactionManager transactionManager, Clock clock, BuildshieldProperties properties) {
        super(jdbc, kafka, json, new TransactionTemplate(transactionManager), clock,
                properties.getMessaging().getTopic(), properties.getMessaging().getBatchSize(),
                properties.getMessaging().getSendTimeout());
    }

    @Scheduled(fixedDelayString = "${buildshield.messaging.outbox-interval:PT0.5S}")
    public void publish() {
        publishPending();
    }
}
