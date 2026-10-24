package pe.buildshield.iam.application;

import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.User;

import java.util.UUID;

/** Vista pública de un usuario, sin credenciales. */
public record UserView(UUID id, String email, String fullName, Role role, boolean active, String phone) {

    public UserView(UUID id, String email, String fullName, Role role, boolean active) {
        this(id, email, fullName, role, active, null);
    }

    static UserView of(User user) {
        return new UserView(user.id(), user.email().value(), user.fullName(), user.role(), user.active(), user.phone());
    }
}
