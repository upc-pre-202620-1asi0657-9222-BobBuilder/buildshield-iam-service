package pe.buildshield.iam.domain.model;

import java.util.UUID;

/**
 * RUC ya registrados (tabla {@code registered_rucs}): un RUC pertenece a una sola organización. Es la
 * única copia del RUC que necesita iam para validar el alta; los datos de la organización viven en
 * Organización y Configuración.
 */
public interface RegisteredRucRepository {

    boolean exists(Ruc ruc);

    /** Registra el RUC dentro de la transacción del alta; un duplicado concurrente viola {@code uk_registered_rucs_ruc}. */
    void register(Ruc ruc, UUID organizationId);
}
