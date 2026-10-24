package pe.buildshield.iam.domain.model;

import pe.buildshield.iam.shared.error.ErrorDetail;
import pe.buildshield.iam.shared.error.ValidationException;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Usuario de una organización. El identificador lo asigna la persistencia al guardarlo por primera
 * vez; hasta entonces {@link #id()} es {@code null}.
 */
public class User {

    static final int MAX_FULL_NAME = 120;
    private static final Pattern PHONE = Pattern.compile("^[+]?[0-9 ]{6,20}$");

    private final UUID id;
    private final UUID organizationId;
    private final EmailAddress email;
    private final String fullName;
    private Role role;
    private String passwordHash;
    private boolean active;
    private String phone;
    private final Long version;

    private User(UUID id, UUID organizationId, EmailAddress email, String fullName, Role role, String passwordHash,
            boolean active, String phone, Long version) {
        this.id = id;
        this.organizationId = Objects.requireNonNull(organizationId, "organizationId");
        this.email = Objects.requireNonNull(email, "email");
        this.fullName = fullName;
        this.role = Objects.requireNonNull(role, "role");
        this.passwordHash = requireHash(passwordHash);
        this.active = active;
        this.phone = phone;
        this.version = version;
    }

    public static User register(UUID organizationId, EmailAddress email, String fullName, Role role, String passwordHash) {
        return register(organizationId, email, fullName, role, passwordHash, null);
    }

    /** @param phone teléfono opcional (columna {@code users.phone} del ER) */
    public static User register(UUID organizationId, EmailAddress email, String fullName, Role role, String passwordHash,
            String phone) {
        if (fullName == null || fullName.isBlank() || fullName.trim().length() > MAX_FULL_NAME) {
            throw new ValidationException("INVALID_FULL_NAME", "El nombre es obligatorio (máximo 120 caracteres)",
                    List.of(new ErrorDetail("fullName", "obligatorio, máximo 120 caracteres")));
        }
        return new User(null, organizationId, email, fullName.trim(), role, passwordHash, true, normalizePhone(phone),
                null);
    }

    public static User restore(UUID id, UUID organizationId, EmailAddress email, String fullName, Role role,
            String passwordHash, boolean active, Long version) {
        return restore(id, organizationId, email, fullName, role, passwordHash, active, null, version);
    }

    public static User restore(UUID id, UUID organizationId, EmailAddress email, String fullName, Role role,
            String passwordHash, boolean active, String phone, Long version) {
        return new User(Objects.requireNonNull(id, "id"), organizationId, email, fullName, role, passwordHash, active,
                phone, version);
    }

    /**
     * Cambia el teléfono; una cadena vacía lo borra. No afecta las sesiones.
     *
     * @return {@code true} si cambió
     */
    public boolean changePhone(String newPhone) {
        String normalized = normalizePhone(newPhone);
        if (Objects.equals(normalized, phone)) {
            return false;
        }
        phone = normalized;
        return true;
    }

    private static String normalizePhone(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        if (!PHONE.matcher(trimmed).matches()) {
            throw new ValidationException("INVALID_PHONE", "El teléfono tiene de 6 a 20 dígitos y puede empezar con +",
                    List.of(new ErrorDetail("phone", "de 6 a 20 dígitos, opcionalmente con + y espacios")));
        }
        return trimmed;
    }

    public void changePasswordHash(String newPasswordHash) {
        this.passwordHash = requireHash(newPasswordHash);
    }

    /**
     * US04: activa o desactiva al usuario y cambia su rol. Un usuario desactivado no inicia sesión.
     *
     * @return {@code true} si cambió el estado o el rol: sus sesiones abiertas deben revocarse
     */
    public boolean update(Boolean newActive, Role newRole) {
        boolean changed = false;
        if (newActive != null && newActive != active) {
            active = newActive;
            changed = true;
        }
        if (newRole != null && newRole != role) {
            role = newRole;
            changed = true;
        }
        return changed;
    }

    public String phone() {
        return phone;
    }

    public boolean canSignIn() {
        return active;
    }

    private static String requireHash(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException("Se requiere el hash de la contraseña");
        }
        return hash;
    }

    public UUID id() {
        return id;
    }

    public UUID organizationId() {
        return organizationId;
    }

    public EmailAddress email() {
        return email;
    }

    public String fullName() {
        return fullName;
    }

    public Role role() {
        return role;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public boolean active() {
        return active;
    }

    public Long version() {
        return version;
    }
}
