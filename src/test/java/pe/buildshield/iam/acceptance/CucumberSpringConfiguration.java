package pe.buildshield.iam.acceptance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.spring.CucumberContextConfiguration;
import io.cucumber.spring.ScenarioScope;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.jdbc.core.JdbcTemplate;
import pe.buildshield.iam.support.ContainersConfig;
import pe.buildshield.iam.support.MutableClock;

import java.time.Instant;
import java.util.List;

/**
 * Contexto de los escenarios: servicio completo en un servidor HTTP real (puerto aleatorio), PostgreSQL real y Kafka embebido, con un reloj controlable.
 * El enlace de recuperación se lee del evento {@code PasswordResetRequested} en el outbox: el correo lo envía
 * Notificaciones, no iam.
 */
@CucumberContextConfiguration
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import({ContainersConfig.class, CucumberSpringConfiguration.AcceptanceBeans.class})
@EmbeddedKafka(kraft = true, partitions = 3, topics = {"buildshield.iam", "buildshield.subscription"},
        bootstrapServersProperty = "spring.kafka.bootstrap-servers")
public class CucumberSpringConfiguration {

    @TestConfiguration(proxyBeanMethods = false)
    static class AcceptanceBeans {

        @Bean
        MutableClock clock() {
            return new MutableClock(Instant.now());
        }

        @Bean
        PasswordResetOutbox passwordResetOutbox(JdbcTemplate jdbc) {
            return new PasswordResetOutbox(jdbc);
        }

        @Bean
        @ScenarioScope
        ScenarioSession scenarioSession(Environment environment, ObjectMapper json) {
            return new ScenarioSession("http://localhost:" + environment.getRequiredProperty("local.server.port"), json);
        }
    }

    /** Solicitudes de recuperación publicadas en el outbox durante el escenario (la base se vacía antes de cada uno). */
    public static class PasswordResetOutbox {

        private final JdbcTemplate jdbc;

        PasswordResetOutbox(JdbcTemplate jdbc) {
            this.jdbc = jdbc;
        }

        public List<SentEmail> sent() {
            return jdbc.query("""
                    SELECT payload -> 'payload' ->> 'email' AS email, payload -> 'payload' ->> 'resetLink' AS link
                    FROM outbox_events WHERE event_type = 'PasswordResetRequested' ORDER BY occurred_at, id
                    """, (rs, row) -> new SentEmail(rs.getString("email"), rs.getString("link")));
        }
    }

    public record SentEmail(String to, String link) {

        public String token() {
            return link.substring(link.indexOf("token=") + "token=".length());
        }
    }
}
