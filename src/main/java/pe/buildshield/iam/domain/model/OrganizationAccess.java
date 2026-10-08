package pe.buildshield.iam.domain.model;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * Estado de la suscripción de una organización, tal como lo informa Suscripción y Pagos
 * ({@code SubscriptionActivated}, {@code SubscriptionExpired}). Al registrarse empieza en prueba
 * gratuita. Con la suscripción vencida la cuenta queda en solo lectura hasta pagar.
 *
 * @param plan       FREE, PLUS o PRO
 * @param validUntil fin del periodo pagado o de la prueba; nulo mientras Suscripción no lo informe
 */
public record OrganizationAccess(UUID organizationId, String plan, Status status, Instant validUntil) {

    public static final String SUBSCRIPTION_READ_ONLY = "SUBSCRIPTION_READ_ONLY";

    public enum Status {
        TRIAL, ACTIVE, EXPIRED;

        /** Acepta el estado tal como llega en el evento; uno desconocido se trata como activo. */
        public static Status parse(String value) {
            if (value == null) {
                return ACTIVE;
            }
            return switch (value.trim().toUpperCase(Locale.ROOT)) {
                case "TRIAL", "TRIALING" -> TRIAL;
                case "EXPIRED", "CANCELED", "CANCELLED", "PAST_DUE" -> EXPIRED;
                default -> ACTIVE;
            };
        }
    }

    public OrganizationAccess {
        Objects.requireNonNull(organizationId, "organizationId");
        Objects.requireNonNull(status, "status");
        plan = plan == null || plan.isBlank() ? "FREE" : plan.trim().toUpperCase(Locale.ROOT);
    }

    /** Prueba gratuita con todas las funciones, al registrar la organización. */
    public static OrganizationAccess trial(UUID organizationId) {
        return new OrganizationAccess(organizationId, "FREE", Status.TRIAL, null);
    }

    public boolean isReadOnly() {
        return status == Status.EXPIRED;
    }
}
