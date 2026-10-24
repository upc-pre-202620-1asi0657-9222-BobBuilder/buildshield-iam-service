package pe.buildshield.iam.application;

import org.springframework.dao.DataIntegrityViolationException;
import pe.buildshield.iam.shared.error.ConflictException;

/**
 * Traduce las violaciones de restricciones UNIQUE (dos altas simultáneas que pasaron la validación
 * previa) al mismo 409 que la validación.
 */
final class UniqueConstraints {

    static final String EMAIL_ALREADY_REGISTERED = "EMAIL_ALREADY_REGISTERED";
    static final String RUC_ALREADY_REGISTERED = "RUC_ALREADY_REGISTERED";

    private UniqueConstraints() {
    }

    static ConflictException emailAlreadyRegistered() {
        return new ConflictException(EMAIL_ALREADY_REGISTERED, "Ya existe un usuario con ese correo");
    }

    static ConflictException rucAlreadyRegistered(String ruc) {
        return new ConflictException(RUC_ALREADY_REGISTERED, "Ya existe una organización con el RUC " + ruc);
    }

    static RuntimeException translate(DataIntegrityViolationException ex) {
        String detail = String.valueOf(ex.getMostSpecificCause().getMessage());
        if (detail.contains("uk_users_email")) {
            return emailAlreadyRegistered();
        }
        if (detail.contains("uk_registered_rucs_ruc") || detail.contains("registered_rucs_pkey")) {
            return new ConflictException(RUC_ALREADY_REGISTERED, "Ya existe una organización con ese RUC");
        }
        return ex;
    }
}
