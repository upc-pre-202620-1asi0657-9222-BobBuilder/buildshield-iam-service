package pe.buildshield.iam.application;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.OrganizationAccess;
import pe.buildshield.iam.domain.model.OrganizationAccessRepository;
import pe.buildshield.iam.domain.model.RegisteredRucRepository;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.Ruc;
import pe.buildshield.iam.domain.model.TokenRepositories.RefreshTokenRepository;
import pe.buildshield.iam.domain.model.TokenRepositories.AccessTokenBlocklist;
import pe.buildshield.iam.domain.model.TokenRepositories.PasswordResetTokenRepository;
import pe.buildshield.iam.domain.model.User;
import pe.buildshield.iam.domain.model.UserRepository;
import pe.buildshield.iam.shared.error.ConflictException;
import pe.buildshield.iam.shared.error.ForbiddenException;
import pe.buildshield.iam.shared.error.ResourceNotFoundException;
import pe.buildshield.iam.shared.error.ValidationException;
import pe.buildshield.iam.shared.messaging.OutboxWriter;
import pe.buildshield.iam.shared.security.JwtTokenProvider;
import pe.buildshield.iam.shared.tenant.MissingTenantContextException;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;
import pe.buildshield.iam.support.TestTransactions;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class IamCommandServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    private final UserRepository users = mock(UserRepository.class);
    private final RegisteredRucRepository rucs = mock(RegisteredRucRepository.class);
    private final OrganizationAccessRepository access = mock(OrganizationAccessRepository.class);
    private final RefreshTokenRepository refreshTokens = mock(RefreshTokenRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final OutboxWriter outbox = mock(OutboxWriter.class);
    private final TestTransactions transactions = new TestTransactions();
    private final IamCommandService service = new IamCommandService(users, rucs, access, refreshTokens,
            mock(PasswordResetTokenRepository.class), mock(AccessTokenBlocklist.class), mock(JwtTokenProvider.class),
            encoder, transactions.template(), outbox, Clock.fixed(NOW, ZoneOffset.UTC),
            new IamProperties(Duration.ofDays(7), Duration.ofMinutes(30), "http://web/reset"));

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    private void savedUsersGetId(UUID id) {
        when(users.save(any())).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            return User.restore(id, user.organizationId(), user.email(), user.fullName(), user.role(),
                    user.passwordHash(), true, 0L);
        });
    }

    private static DataIntegrityViolationException violation(String message) {
        return new DataIntegrityViolationException("could not execute statement", new SQLException(message));
    }

    /** US01: alta de la organización y su administrador. */
    @Nested
    class SignUp {

        private final IamCommandService.SignUpCommand command = new IamCommandService.SignUpCommand(
                "20123456789", "Constructora Andina SAC", "Ana Torres", "Ana@Andina.pe", "Segura123");

        @Test
        void registers_ruc_administrator_trial_and_events_in_one_transaction_under_the_new_organization() {
            when(encoder.encode("Segura123")).thenReturn("$2a$12$hash");
            AtomicReference<TenantInfo> contextWhileRegistering = new AtomicReference<>();
            doAnswer(invocation -> {
                contextWhileRegistering.set(TenantContext.require());
                return null;
            }).when(rucs).register(any(), any());
            UUID adminId = UUID.randomUUID();
            savedUsersGetId(adminId);

            IamCommandService.SignUpResult result = service.signUp(command);

            assertThat(result.administratorId()).isEqualTo(adminId);
            assertThat(contextWhileRegistering.get().organizationId()).isEqualTo(result.organizationId());
            assertThat(contextWhileRegistering.get().role()).isEqualTo("ADMINISTRATOR");
            verify(rucs).register(new Ruc("20123456789"), result.organizationId());
            verify(users).save(argThat(user -> user.role() == Role.ADMINISTRATOR
                    && user.email().equals(new EmailAddress("ana@andina.pe"))
                    && user.passwordHash().equals("$2a$12$hash")
                    && user.organizationId().equals(result.organizationId())));
            verify(access).save(OrganizationAccess.trial(result.organizationId()));
            verify(outbox).append(result.organizationId(), adminId, IamEvents.ORGANIZATION_REGISTERED,
                    IamEvents.ORGANIZATION, result.organizationId(), new IamEvents.OrganizationRegistered(
                            result.organizationId(), "20123456789", "Constructora Andina SAC", adminId,
                            "ana@andina.pe", "Ana Torres"));
            verify(outbox).append(result.organizationId(), adminId, IamEvents.USER_CREATED, IamEvents.USER, adminId,
                    new IamEvents.UserCreated(adminId, "Ana Torres", "ana@andina.pe", "ADMINISTRATOR", true));
            assertThat(transactions.commits).hasValue(1);
            assertThat(TenantContext.current()).isEmpty();
        }

        @Test
        void registered_ruc_is_a_conflict_and_nothing_is_stored() {
            when(encoder.encode(anyString())).thenReturn("hash");
            when(rucs.exists(new Ruc("20123456789"))).thenReturn(true);

            assertThatThrownBy(() -> service.signUp(command))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", "RUC_ALREADY_REGISTERED")
                    .hasMessage("Ya existe una organización con el RUC 20123456789");
            assertThat(transactions.rollbacks).hasValue(1);
            verify(users, never()).save(any());
            verifyNoInteractions(outbox);
        }

        @Test
        void registered_email_rolls_back_the_organization() {
            when(encoder.encode(anyString())).thenReturn("hash");
            when(users.existsByEmailInAnyOrganization(new EmailAddress("ana@andina.pe"))).thenReturn(true);

            assertThatThrownBy(() -> service.signUp(command))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", "EMAIL_ALREADY_REGISTERED");
            assertThat(transactions.rollbacks).hasValue(1);
            assertThat(transactions.commits).hasValue(0);
            verify(users, never()).save(any());
            verifyNoInteractions(outbox);
        }

        @Test
        void weak_password_is_rejected_before_opening_a_transaction() {
            IamCommandService.SignUpCommand weak = new IamCommandService.SignUpCommand(
                    "20123456789", "Andina", "Ana", "ana@andina.pe", "corta");

            assertThatThrownBy(() -> service.signUp(weak)).isInstanceOf(ValidationException.class);
            verifyNoInteractions(rucs, users, encoder, outbox);
        }

        @Test
        void invalid_email_ruc_or_legal_name_are_rejected_before_opening_a_transaction() {
            assertThatThrownBy(() -> service.signUp(new IamCommandService.SignUpCommand(
                    "20123456789", "Andina", "Ana", "no-es-correo", "Segura123"))).isInstanceOf(ValidationException.class);
            assertThatThrownBy(() -> service.signUp(new IamCommandService.SignUpCommand(
                    "2012345", "Andina", "Ana", "ana@andina.pe", "Segura123")))
                    .isInstanceOf(ValidationException.class).hasFieldOrPropertyWithValue("code", "INVALID_RUC");
            assertThatThrownBy(() -> service.signUp(new IamCommandService.SignUpCommand(
                    "20123456789", " ", "Ana", "ana@andina.pe", "Segura123")))
                    .isInstanceOf(ValidationException.class).hasFieldOrPropertyWithValue("code", "INVALID_LEGAL_NAME");
            verifyNoInteractions(rucs, users, outbox);
            assertThat(transactions.commits).hasValue(0);
        }

        @Test
        void concurrent_duplicate_email_detected_by_the_database_is_a_409() {
            when(encoder.encode(anyString())).thenReturn("hash");
            when(users.save(any())).thenThrow(violation("duplicate key value violates unique constraint \"uk_users_email\""));

            assertThatThrownBy(() -> service.signUp(command))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", "EMAIL_ALREADY_REGISTERED");
        }

        @Test
        void concurrent_duplicate_ruc_detected_by_the_database_is_a_409() {
            when(encoder.encode(anyString())).thenReturn("hash");
            doThrow(violation("duplicate key value violates unique constraint \"uk_registered_rucs_ruc\""))
                    .when(rucs).register(eq(new Ruc("20123456789")), any());

            assertThatThrownBy(() -> service.signUp(command))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", "RUC_ALREADY_REGISTERED");
        }

        @Test
        void other_integrity_violations_propagate() {
            when(encoder.encode(anyString())).thenReturn("hash");
            DataIntegrityViolationException other = violation("null value in column \"full_name\"");
            when(users.save(any())).thenThrow(other);

            assertThatThrownBy(() -> service.signUp(command)).isSameAs(other);
        }
    }

    /** US04: gestión de usuarios y roles por el administrador. */
    @Nested
    class UserManagement {

        private final UUID org = UUID.randomUUID();
        private final UUID admin = UUID.randomUUID();

        UserManagement() {
            TenantContext.set(new TenantInfo(org, admin, "ADMINISTRATOR"));
            when(encoder.encode(anyString())).thenReturn("$2a$12$hash");
        }

        private User stored(UUID id, Role role, boolean active) {
            return User.restore(id, org, new EmailAddress("rosa@andina.pe"), "Rosa", role, "h", active, 1L);
        }

        @Test
        void creates_the_user_in_the_administrator_organization_and_publishes_user_created() {
            UUID id = UUID.randomUUID();
            savedUsersGetId(id);

            UserView view = service.createUser(new IamCommandService.CreateUserCommand("Rosa Quispe", "Rosa@Andina.pe",
                    "WAREHOUSE_MANAGER", "Almacen123"));

            assertThat(view).isEqualTo(new UserView(id, "rosa@andina.pe", "Rosa Quispe", Role.WAREHOUSE_MANAGER, true));
            verify(users).save(argThat(user -> user.organizationId().equals(org) && user.passwordHash().equals("$2a$12$hash")));
            verify(outbox).append(IamEvents.USER_CREATED, IamEvents.USER, id,
                    new IamEvents.UserCreated(id, "Rosa Quispe", "rosa@andina.pe", "WAREHOUSE_MANAGER", true));
        }

        @Test
        void registered_email_is_a_conflict() {
            when(users.existsByEmailInAnyOrganization(new EmailAddress("rosa@andina.pe"))).thenReturn(true);

            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Rosa", "rosa@andina.pe", "SITE_MANAGER", "Obra12345")))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", "EMAIL_ALREADY_REGISTERED");
            verify(users, never()).save(any());
        }

        @Test
        void concurrent_duplicate_email_is_a_conflict() {
            when(users.save(any())).thenThrow(violation("duplicate key value violates unique constraint \"uk_users_email\""));

            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Rosa", "rosa@andina.pe", "SITE_MANAGER", "Obra12345")))
                    .isInstanceOf(ConflictException.class);
        }

        @Test
        void invalid_role_or_weak_password_are_rejected() {
            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Pedro", "pedro@andina.pe", "gerente", "Gerente123")))
                    .isInstanceOf(ValidationException.class).hasFieldOrPropertyWithValue("code", "INVALID_ROLE");
            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Pedro", "pedro@andina.pe", "SITE_MANAGER", "123")))
                    .isInstanceOf(ValidationException.class).hasFieldOrPropertyWithValue("code", "WEAK_PASSWORD");
            verify(users, never()).save(any());
        }

        @Test
        void creating_without_organization_fails_safely() {
            TenantContext.clear();

            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Pedro", "pedro@andina.pe", "SITE_MANAGER", "Obra12345")))
                    .isInstanceOf(MissingTenantContextException.class);
        }

        @Test
        void an_expired_subscription_leaves_users_read_only() {
            UUID rosa = UUID.randomUUID();
            when(access.find(org)).thenReturn(Optional.of(new OrganizationAccess(org,
                    OrganizationAccess.AccessMode.READ_ONLY)));
            when(users.findById(rosa)).thenReturn(Optional.of(stored(rosa, Role.WAREHOUSE_MANAGER, true)));

            assertThatThrownBy(() -> service.createUser(
                    new IamCommandService.CreateUserCommand("Pedro", "pedro@andina.pe", "SITE_MANAGER", "Obra12345")))
                    .isInstanceOf(ForbiddenException.class)
                    .hasFieldOrPropertyWithValue("code", OrganizationAccess.SUBSCRIPTION_READ_ONLY);
            assertThatThrownBy(() -> service.updateUser(rosa, new IamCommandService.UpdateUserCommand(false, null)))
                    .isInstanceOf(ForbiddenException.class);
            verify(users, never()).save(any());
        }

        @Test
        void deactivating_a_user_revokes_its_sessions_and_publishes_user_updated() {
            UUID rosa = UUID.randomUUID();
            when(users.findById(rosa)).thenReturn(Optional.of(stored(rosa, Role.WAREHOUSE_MANAGER, true)));
            when(users.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

            UserView view = service.updateUser(rosa, new IamCommandService.UpdateUserCommand(false, null));

            assertThat(view.active()).isFalse();
            verify(refreshTokens).revokeAllActive(rosa, NOW);
            verify(outbox).append(IamEvents.USER_UPDATED, IamEvents.USER, rosa,
                    new IamEvents.UserUpdated(rosa, "Rosa", "rosa@andina.pe", "WAREHOUSE_MANAGER", false));
        }

        @Test
        void changing_the_role_revokes_sessions_and_nothing_changes_without_differences() {
            UUID rosa = UUID.randomUUID();
            when(users.findById(rosa)).thenReturn(Optional.of(stored(rosa, Role.WAREHOUSE_MANAGER, true)));
            when(users.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

            assertThat(service.updateUser(rosa, new IamCommandService.UpdateUserCommand(null, "SITE_MANAGER")).role())
                    .isEqualTo(Role.SITE_MANAGER);
            verify(refreshTokens).revokeAllActive(rosa, NOW);

            when(users.findById(rosa)).thenReturn(Optional.of(stored(rosa, Role.SITE_MANAGER, true)));
            service.updateUser(rosa, new IamCommandService.UpdateUserCommand(true, "SITE_MANAGER"));
            verify(users, times(1)).save(any());
            verify(outbox, times(1)).append(eq(IamEvents.USER_UPDATED), anyString(), any(), any());
        }

        @Test
        void the_administrator_cannot_deactivate_itself_or_change_its_role() {
            when(users.findById(admin)).thenReturn(Optional.of(stored(admin, Role.ADMINISTRATOR, true)));

            assertThatThrownBy(() -> service.updateUser(admin, new IamCommandService.UpdateUserCommand(false, null)))
                    .isInstanceOf(ConflictException.class)
                    .hasFieldOrPropertyWithValue("code", IamCommandService.CANNOT_CHANGE_OWN_ACCOUNT);
            assertThatThrownBy(() -> service.updateUser(admin, new IamCommandService.UpdateUserCommand(null, "SITE_MANAGER")))
                    .isInstanceOf(ConflictException.class);
            verify(users, never()).save(any());
        }

        @Test
        void update_requires_a_change_an_existing_user_and_a_valid_role() {
            assertThatThrownBy(() -> service.updateUser(UUID.randomUUID(), new IamCommandService.UpdateUserCommand(null, " ")))
                    .isInstanceOf(ValidationException.class).hasFieldOrPropertyWithValue("code", "EMPTY_UPDATE");
            assertThatThrownBy(() -> service.updateUser(UUID.randomUUID(), new IamCommandService.UpdateUserCommand(null, "gerente")))
                    .isInstanceOf(ValidationException.class);
            when(users.findById(any())).thenReturn(Optional.empty());
            assertThatThrownBy(() -> service.updateUser(UUID.randomUUID(), new IamCommandService.UpdateUserCommand(false, null)))
                    .isInstanceOf(ResourceNotFoundException.class).hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");
        }

        @Test
        void the_subscription_status_is_stored() {
            OrganizationAccess active = new OrganizationAccess(org, OrganizationAccess.AccessMode.FULL);

            service.applySubscriptionStatus(active);

            verify(access).save(active);
        }
    }

    @Test
    void lists_the_users_returned_for_the_organization() {
        UUID org = UUID.randomUUID();
        when(users.findAll()).thenReturn(List.of(User.restore(UUID.randomUUID(), org, new EmailAddress("ana@andina.pe"),
                "Ana", Role.ADMINISTRATOR, "h", true, 0L)));

        assertThat(new IamQueryService(users).listUsers()).extracting(UserView::email).containsExactly("ana@andina.pe");
    }
}
