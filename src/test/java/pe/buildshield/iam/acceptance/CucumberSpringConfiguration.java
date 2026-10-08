package pe.buildshield.iam.acceptance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.spring.CucumberContextConfiguration;
import io.cucumber.spring.ScenarioScope;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.ActiveProfiles;
import pe.buildshield.iam.application.EmailPort;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.support.ContainersConfig;
import pe.buildshield.iam.support.MutableClock;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Contexto de los escenarios: servicio completo en un servidor HTTP real (puerto aleatorio), PostgreSQL real y Kafka embebido, con un reloj controlable y
 * un {@link EmailPort} que guarda los correos para leer el enlace de recuperación.
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
        @Primary
        CapturingEmailPort capturingEmailPort() {
            return new CapturingEmailPort();
        }

        @Bean
        @ScenarioScope
        ScenarioSession scenarioSession(Environment environment, ObjectMapper json) {
            return new ScenarioSession("http://localhost:" + environment.getRequiredProperty("local.server.port"), json);
        }
    }

    /** Correos "enviados" durante el escenario. */
    public static class CapturingEmailPort implements EmailPort {

        private final List<SentEmail> sent = new CopyOnWriteArrayList<>();

        @Override
        public void sendPasswordReset(EmailAddress to, String fullName, String resetLink, Instant expiresAt) {
            sent.add(new SentEmail(to.value(), resetLink));
        }

        public List<SentEmail> sent() {
            return sent;
        }

        public void clear() {
            sent.clear();
        }
    }

    public record SentEmail(String to, String link) {

        public String token() {
            return link.substring(link.indexOf("token=") + "token=".length());
        }
    }
}
