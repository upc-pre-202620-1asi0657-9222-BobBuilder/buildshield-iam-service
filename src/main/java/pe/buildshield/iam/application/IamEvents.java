package pe.buildshield.iam.application;

import java.time.Instant;
import java.util.UUID;

/**
 * Eventos de integración que publica iam en el tópico {@code buildshield.iam} (payload del sobre).
 * Los nombres de los campos son el contrato con los demás servicios: no se renombran.
 */
public final class IamEvents {

    public static final String ORGANIZATION_REGISTERED = "OrganizationRegistered";
    public static final String USER_CREATED = "UserCreated";
    public static final String USER_UPDATED = "UserUpdated";
    public static final String PASSWORD_RESET_REQUESTED = "PasswordResetRequested";

    public static final String ORGANIZATION = "ORGANIZATION";
    public static final String USER = "USER";

    private IamEvents() {
    }

    /** Alta de una empresa cliente con su administrador (US01). */
    public record OrganizationRegistered(UUID organizationId, String ruc, String legalName, UUID adminUserId,
            String adminEmail, String adminFullName) {
    }

    /** Usuario creado (también el administrador del alta). */
    public record UserCreated(UUID userId, String fullName, String email, String role, boolean active) {
    }

    /** Cambio de rol o de estado (desactivado o reactivado). */
    public record UserUpdated(UUID userId, String fullName, String email, String role, boolean active) {
    }

    /**
     * Solicitud de recuperación de contraseña (US05). Notificaciones envía el correo con {@code resetLink}, que
     * es una credencial de un solo uso: no se registra en logs ni en la bitácora de auditoría.
     */
    public record PasswordResetRequested(UUID userId, String email, String fullName, String resetLink,
            Instant expiresAt) {
    }
}
