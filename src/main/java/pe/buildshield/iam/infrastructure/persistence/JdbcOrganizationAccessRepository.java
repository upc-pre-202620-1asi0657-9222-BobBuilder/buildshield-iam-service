package pe.buildshield.iam.infrastructure.persistence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import pe.buildshield.iam.domain.model.OrganizationAccess;
import pe.buildshield.iam.domain.model.OrganizationAccessRepository;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/** Tabla {@code organization_access}, una fila por organización. */
@Repository
class JdbcOrganizationAccessRepository implements OrganizationAccessRepository {

    private final JdbcTemplate jdbc;
    private final Clock clock;

    JdbcOrganizationAccessRepository(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public Optional<OrganizationAccess> find(UUID organizationId) {
        return jdbc.query("SELECT organization_id, access_mode FROM organization_access WHERE organization_id = ?",
                (rs, row) -> new OrganizationAccess(rs.getObject("organization_id", UUID.class),
                        OrganizationAccess.AccessMode.valueOf(rs.getString("access_mode"))),
                organizationId).stream().findFirst();
    }

    @Override
    public void save(OrganizationAccess access) {
        jdbc.update("""
                INSERT INTO organization_access (organization_id, access_mode, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT (organization_id) DO UPDATE SET access_mode = EXCLUDED.access_mode,
                    updated_at = EXCLUDED.updated_at
                """, access.organizationId(), access.accessMode().name(), Timestamp.from(clock.instant()));
    }
}
