package pe.buildshield.iam.support;

import org.springframework.boot.autoconfigure.jdbc.JdbcConnectionDetails;
import org.springframework.core.env.Environment;

/**
 * Opt-in explícito a una base temporal externa: nunca acepta una base de trabajo. Se activa con
 * {@code -Dbuildshield.test.external-database=true -Dbuildshield.test.<servicio>-url=jdbc:postgresql://127.0.0.1:5433/<servicio>_it
 * -Dbuildshield.test.database-user=...}.
 */
public final class ExternalPostgres {

    private ExternalPostgres() {
    }

    public static JdbcConnectionDetails connection(Environment env, String service) {
        String url = env.getRequiredProperty("buildshield.test." + service + "-url");
        if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/" + service + "_it")) {
            throw new IllegalArgumentException("Se requiere una base temporal local " + service + "_it");
        }
        String user = env.getRequiredProperty("buildshield.test.database-user");
        String password = env.getProperty("buildshield.test.database-password", "");
        return new JdbcConnectionDetails() {
            @Override
            public String getJdbcUrl() {
                return url;
            }

            @Override
            public String getUsername() {
                return user;
            }

            @Override
            public String getPassword() {
                return password;
            }

            @Override
            public String getDriverClassName() {
                return "org.postgresql.Driver";
            }
        };
    }
}
