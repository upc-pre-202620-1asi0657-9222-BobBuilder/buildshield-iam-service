package pe.buildshield.iam.application;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.Permission;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.User;
import pe.buildshield.iam.domain.model.UserRepository;
import pe.buildshield.iam.shared.error.ResourceNotFoundException;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IamQueryServiceTest {

    private static final UUID ORG = UUID.randomUUID();
    private static final UUID ROSA = UUID.randomUUID();

    private final UserRepository users = mock(UserRepository.class);
    private final IamQueryService service = new IamQueryService(users);

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    private static User rosa() {
        return User.restore(ROSA, ORG, new EmailAddress("rosa@andina.pe"), "Rosa", Role.WAREHOUSE_MANAGER, "$2a$hash",
                true, "987654321", 0L);
    }

    @Test
    void lists_and_finds_users_with_their_phone() {
        when(users.findAll()).thenReturn(List.of(rosa()));
        when(users.findById(ROSA)).thenReturn(Optional.of(rosa()));

        assertThat(service.listUsers()).extracting(UserView::phone).containsExactly("987654321");
        assertThat(service.getUser(ROSA).email()).isEqualTo("rosa@andina.pe");
        UUID unknown = UUID.randomUUID();
        assertThatThrownBy(() -> service.getUser(unknown)).isInstanceOf(ResourceNotFoundException.class)
                .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");
    }

    @Test
    void current_user_comes_with_the_permissions_of_its_role() {
        when(users.findById(ROSA)).thenReturn(Optional.of(rosa()));

        IamQueryService.Profile profile = TenantContext.callAs(
                new TenantInfo(ORG, ROSA, Role.WAREHOUSE_MANAGER.name()), service::currentUser);

        assertThat(profile.user().id()).isEqualTo(ROSA);
        assertThat(profile.permissions()).containsExactly(Permission.ATTEND_ORDERS, Permission.REGISTER_DISPATCHES);
    }
}
