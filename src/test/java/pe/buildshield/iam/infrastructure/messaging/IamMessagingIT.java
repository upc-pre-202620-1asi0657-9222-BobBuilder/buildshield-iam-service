package pe.buildshield.iam.infrastructure.messaging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import pe.buildshield.iam.application.IamCommandService;
import pe.buildshield.iam.shared.error.ForbiddenException;
import pe.buildshield.iam.shared.messaging.Topics;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;
import pe.buildshield.iam.support.IamIntegrationTest;
import pe.buildshield.iam.support.TestDatabase;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * Eventos de iam contra Kafka embebido y PostgreSQL real: el outbox llega al tópico {@code buildshield.iam}
 * con el sobre común, y los eventos de Suscripción actualizan {@code organization_access} una sola vez.
 */
@IamIntegrationTest
class IamMessagingIT {

    @Autowired
    IamCommandService commands;

    @Autowired
    IamOutboxPublisher publisher;

    @Autowired
    KafkaTemplate<String, String> kafka;

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    ObjectMapper json;

    @Value("${spring.kafka.bootstrap-servers}")
    String bootstrapServers;

    @BeforeEach
    void clean() {
        TestDatabase.reset(jdbc);
    }

    @Test
    void sign_up_events_reach_the_iam_topic_with_the_common_envelope() throws Exception {
        IamCommandService.SignUpResult result = commands.signUp(new IamCommandService.SignUpCommand(
                "20123456789", "Constructora Andina SAC", "Ana Torres", "ana@andina.pe", "Segura123"));

        assertThat(publisher.publishPending()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM outbox_events WHERE published_at IS NULL", Long.class))
                .isZero();
        assertThat(publisher.publishPending()).isZero();

        List<ConsumerRecord<String, String>> records = readIamTopic(result.organizationId(), 2);
        ConsumerRecord<String, String> registered = records.stream()
                .filter(record -> record.value().contains("OrganizationRegistered")).findFirst().orElseThrow();
        assertThat(registered.key()).isEqualTo(result.organizationId().toString());
        JsonNode envelope = json.readTree(registered.value());
        assertThat(envelope.get("eventType").asText()).isEqualTo("OrganizationRegistered");
        assertThat(envelope.get("aggregateType").asText()).isEqualTo("ORGANIZATION");
        assertThat(envelope.get("version").asInt()).isEqualTo(1);
        assertThat(envelope.get("actorId").asText()).isEqualTo(result.administratorId().toString());
        assertThat(envelope.hasNonNull("eventId")).isTrue();
        assertThat(envelope.hasNonNull("occurredAt")).isTrue();
        JsonNode payload = envelope.get("payload");
        assertThat(payload.get("organizationId").asText()).isEqualTo(result.organizationId().toString());
        assertThat(payload.get("ruc").asText()).isEqualTo("20123456789");
        assertThat(payload.get("legalName").asText()).isEqualTo("Constructora Andina SAC");
        assertThat(payload.get("adminUserId").asText()).isEqualTo(result.administratorId().toString());
        assertThat(payload.get("adminEmail").asText()).isEqualTo("ana@andina.pe");

        ConsumerRecord<String, String> userCreated = records.stream()
                .filter(record -> record.value().contains("UserCreated")).findFirst().orElseThrow();
        assertThat(userCreated.key()).isEqualTo(result.administratorId().toString());
        JsonNode user = json.readTree(userCreated.value()).get("payload");
        assertThat(user.get("role").asText()).isEqualTo("ADMINISTRATOR");
        assertThat(user.get("active").asBoolean()).isTrue();
    }

    @Test
    void subscription_events_update_the_organization_access_once() {
        IamCommandService.SignUpResult result = commands.signUp(new IamCommandService.SignUpCommand(
                "20123456789", "Constructora Andina SAC", "Ana Torres", "ana@andina.pe", "Segura123"));
        UUID organizationId = result.organizationId();

        UUID activated = UUID.randomUUID();
        kafka.send(Topics.SUBSCRIPTION, organizationId.toString(), subscriptionEvent(activated,
                "SubscriptionActivated", organizationId, "PLUS", "ACTIVE", "2026-12-31T00:00:00Z"));
        await().atMost(Duration.ofSeconds(20)).until(() -> "ACTIVE".equals(accessStatus(organizationId)));
        assertThat(jdbc.queryForObject("SELECT plan FROM organization_access WHERE organization_id = ?",
                String.class, organizationId)).isEqualTo("PLUS");

        UUID expired = UUID.randomUUID();
        String expiredEvent = subscriptionEvent(expired, "SubscriptionExpired", organizationId, "PLUS", "EXPIRED",
                "2026-12-31");
        kafka.send(Topics.SUBSCRIPTION, organizationId.toString(), expiredEvent);
        await().atMost(Duration.ofSeconds(20)).until(() -> "EXPIRED".equals(accessStatus(organizationId)));

        // Reentrega del mismo evento después de reactivar a mano: no se vuelve a aplicar.
        jdbc.update("UPDATE organization_access SET status = 'ACTIVE' WHERE organization_id = ?", organizationId);
        kafka.send(Topics.SUBSCRIPTION, organizationId.toString(), expiredEvent);
        UUID marker = UUID.randomUUID();
        kafka.send(Topics.SUBSCRIPTION, organizationId.toString(), subscriptionEvent(marker, "PlanChanged",
                organizationId, "PRO", "ACTIVE", null));
        await().atMost(Duration.ofSeconds(20)).until(() -> processed(marker));
        assertThat(accessStatus(organizationId)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM processed_events WHERE event_id = ?", Long.class,
                expired)).isEqualTo(1);

        // Vencida, la cuenta queda en solo lectura para crear usuarios.
        jdbc.update("UPDATE organization_access SET status = 'EXPIRED' WHERE organization_id = ?", organizationId);
        TenantInfo admin = new TenantInfo(organizationId, result.administratorId(), "ADMINISTRATOR");
        assertThatThrownBy(() -> TenantContext.runAs(admin, () -> commands.createUser(
                new IamCommandService.CreateUserCommand("Rosa", "rosa@andina.pe", "WAREHOUSE_MANAGER", "Almacen123"))))
                .isInstanceOf(ForbiddenException.class)
                .hasFieldOrPropertyWithValue("code", "SUBSCRIPTION_READ_ONLY");
    }

    private String accessStatus(UUID organizationId) {
        return jdbc.queryForList("SELECT status FROM organization_access WHERE organization_id = ?", String.class,
                organizationId).stream().findFirst().orElse(null);
    }

    private boolean processed(UUID eventId) {
        return jdbc.queryForObject("SELECT count(*) FROM processed_events WHERE event_id = ?", Long.class, eventId) == 1;
    }

    private String subscriptionEvent(UUID eventId, String type, UUID organizationId, String plan, String status,
            String validUntil) {
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("organizationId", organizationId);
        payload.put("plan", plan);
        payload.put("status", status);
        payload.put("validUntil", validUntil);
        Map<String, Object> envelope = new java.util.LinkedHashMap<>();
        envelope.put("eventId", eventId);
        envelope.put("eventType", type);
        envelope.put("occurredAt", Instant.now().toString());
        envelope.put("organizationId", organizationId);
        envelope.put("aggregateType", "SUBSCRIPTION");
        envelope.put("aggregateId", organizationId.toString());
        envelope.put("actorId", null);
        envelope.put("version", 1);
        envelope.put("payload", payload);
        try {
            return json.writeValueAsString(envelope);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private List<ConsumerRecord<String, String>> readIamTopic(UUID organizationId, int expected) {
        Map<String, Object> props = Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers,
                ConsumerConfig.GROUP_ID_CONFIG, "iam-it-" + UUID.randomUUID(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        List<ConsumerRecord<String, String>> found = new ArrayList<>();
        try (Consumer<String, String> consumer = new DefaultKafkaConsumerFactory<String, String>(props).createConsumer()) {
            consumer.subscribe(List.of(Topics.IAM));
            long deadline = System.currentTimeMillis() + 20_000;
            while (found.size() < expected && System.currentTimeMillis() < deadline) {
                consumer.poll(Duration.ofMillis(500)).forEach(record -> {
                    if (record.value().contains(organizationId.toString())) {
                        found.add(record);
                    }
                });
            }
        }
        assertThat(found).hasSize(expected);
        return found;
    }
}
