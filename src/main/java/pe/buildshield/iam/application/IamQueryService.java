package pe.buildshield.iam.application;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.buildshield.iam.domain.model.UserRepository;

import java.util.List;

/** Consultas de iam: los usuarios de la organización del token (US04). */
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
}
