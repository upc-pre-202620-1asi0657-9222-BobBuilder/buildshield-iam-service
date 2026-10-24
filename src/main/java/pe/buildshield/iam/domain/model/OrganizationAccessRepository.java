package pe.buildshield.iam.domain.model;

import java.util.Optional;
import java.util.UUID;

/** Tabla {@code organization_access}: una fila por organización, alimentada por eventos de Suscripción. */
public interface OrganizationAccessRepository {

    Optional<OrganizationAccess> find(UUID organizationId);

    /** Inserta o reemplaza el estado de la organización. */
    void save(OrganizationAccess access);
}
