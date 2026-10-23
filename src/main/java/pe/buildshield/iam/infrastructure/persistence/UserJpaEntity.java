package pe.buildshield.iam.infrastructure.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import pe.buildshield.iam.shared.persistence.AuditableAbstractAggregateRoot;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.User;

/**
 * Modelo de persistencia de {@link User}. Hereda {@code organization_id} (filtro multiempresa),
 * auditoría y {@code version}.
 */
@Entity
@Table(name = "users")
public class UserJpaEntity extends AuditableAbstractAggregateRoot<UserJpaEntity> {

    @Column(name = "email", nullable = false, length = 120)
    private String email;

    @Column(name = "full_name", nullable = false, length = 120)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private Role role;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "active", nullable = false)
    private boolean active;

    protected UserJpaEntity() {
    }

    UserJpaEntity(User user) {
        apply(user);
    }

    void apply(User user) {
        email = user.email().value();
        fullName = user.fullName();
        role = user.role();
        passwordHash = user.passwordHash();
        active = user.active();
    }

    User toDomain() {
        return User.restore(getId(), getOrganizationId(), new EmailAddress(email), fullName, role, passwordHash,
                active, getVersion());
    }
}
