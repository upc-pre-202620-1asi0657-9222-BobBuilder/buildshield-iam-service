package pe.buildshield.iam.domain.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Modo de acceso de una organización según su suscripción, tal como lo informa Suscripción y Pagos
 * ({@code SubscriptionActivated}, {@code SubscriptionExpired}). Al registrarse empieza con acceso
 * completo (prueba gratuita). Con la suscripción vencida la cuenta queda en solo lectura hasta pagar.
 */
public record OrganizationAccess(UUID organizationId, AccessMode accessMode) {

    public static final String SUBSCRIPTION_READ_ONLY = "SUBSCRIPTION_READ_ONLY";

    /** Columna {@code access_mode} de {@code organization_access}. */
    public enum AccessMode {
        FULL, READ_ONLY
    }

    public OrganizationAccess {
        Objects.requireNonNull(organizationId, "organizationId");
        Objects.requireNonNull(accessMode, "accessMode");
    }

    /** Prueba gratuita con todas las funciones, al registrar la organización. */
    public static OrganizationAccess trial(UUID organizationId) {
        return new OrganizationAccess(organizationId, AccessMode.FULL);
    }

    public boolean isReadOnly() {
        return accessMode == AccessMode.READ_ONLY;
    }
}
