package pe.buildshield.iam.application;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.buildshield.iam.domain.model.Permission;
import pe.buildshield.iam.domain.model.UserRepository;
import pe.buildshield.iam.shared.error.ResourceNotFoundException;
import pe.buildshield.iam.shared.tenant.TenantContext;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * IAM QueryService del C4 (pág. 27 de la v4): consultas de usuarios y permisos, siempre dentro de la
 * organización del token (US04).
 */
@Service
public class IamQueryService {

    private final UserRepository users;

    public IamQueryService(UserRepository users) {
        this.users = users;
    }

    @Transactional(readOnly = true)
    public List<UserView> listUsers() {
        return users.findAll().stream().map(UserView::of).toList();
    }

    @Transactional(readOnly = true)
    public UserView getUser(UUID userId) {
        return users.findById(userId).map(UserView::of)
                .orElseThrow(() -> new ResourceNotFoundException("USER_NOT_FOUND", "El usuario " + userId + " no existe"));
    }

    /** Usuario del token con los permisos de su rol. */
    @Transactional(readOnly = true)
    public Profile currentUser() {
        UserView user = getUser(TenantContext.require().userId());
        return new Profile(user, user.role().permissions());
    }

    public record Profile(UserView user, Set<Permission> permissions) {
    }
}
