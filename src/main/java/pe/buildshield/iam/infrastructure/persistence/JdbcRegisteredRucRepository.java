package pe.buildshield.iam.infrastructure.persistence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import pe.buildshield.iam.domain.model.RegisteredRucRepository;
import pe.buildshield.iam.domain.model.Ruc;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;

/** Tabla {@code registered_rucs}. JDBC directo: se consulta entre todas las organizaciones. */
@Repository
class JdbcRegisteredRucRepository implements RegisteredRucRepository {

    private final JdbcTemplate jdbc;
    private final Clock clock;

    JdbcRegisteredRucRepository(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public boolean exists(Ruc ruc) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM registered_rucs WHERE ruc = ?)", Boolean.class, ruc.value()));
    }

    @Override
    public void register(Ruc ruc, UUID organizationId) {
        jdbc.update("INSERT INTO registered_rucs (ruc, organization_id, registered_at) VALUES (?, ?, ?)",
                ruc.value(), organizationId, Timestamp.from(clock.instant()));
    }
}
