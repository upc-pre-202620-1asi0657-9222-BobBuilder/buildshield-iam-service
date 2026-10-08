package pe.buildshield.iam.infrastructure.persistence;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import pe.buildshield.iam.shared.error.ConflictException;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;
import pe.buildshield.iam.application.IamCommandService;
import pe.buildshield.iam.support.TestDatabase;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.User;
import pe.buildshield.iam.domain.model.UserRepository;
import pe.buildshield.iam.support.IamIntegrationTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Registro y usuarios contra PostgreSQL real, con el filtro multiempresa del kernel compartido. */
@IamIntegrationTest
class IamPersistenceIT {

    @Autowired
    IamCommandService signUp;

    @Autowired
    UserRepository users;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        TestDatabase.reset(jdbc);
    }

    @Test
    void sign_up_stores_the_organization_and_its_administrator() {
        IamCommandService.SignUpResult result = signUp.signUp(command("20123456789", "ana@andina.pe"));

        assertThat(jdbc.queryForObject("SELECT organization_id FROM registered_rucs WHERE ruc = '20123456789'",
                UUID.class)).isEqualTo(result.organizationId());
        assertThat(jdbc.queryForObject("SELECT status FROM organization_access WHERE organization_id = ?",
                String.class, result.organizationId())).isEqualTo("TRIAL");
        assertThat(jdbc.queryForList("SELECT event_type FROM outbox_events WHERE organization_id = ? ORDER BY event_type",
                String.class, result.organizationId())).containsExactly("OrganizationRegistered", "UserCreated");
        assertThat(jdbc.queryForObject("""
                SELECT payload ->> 'legalName' FROM outbox_events
                WHERE event_type = 'OrganizationRegistered' AND aggregate_id = ?""", String.class,
                result.organizationId().toString())).isEqualTo("Constructora 20123456789");
        assertThat(jdbc.queryForMap("SELECT organization_id, role, email, created_by FROM users WHERE id = ?",
                result.administratorId()))
                .containsEntry("organization_id", result.organizationId())
                .containsEntry("role", "ADMINISTRATOR")
                .containsEntry("email", "ana@andina.pe")
                .containsEntry("created_by", TenantContext.SYSTEM_USER_ID);
        String hash = jdbc.queryForObject("SELECT password_hash FROM users WHERE id = ?", String.class,
                result.administratorId());
        assertThat(hash).startsWith("$2a$12$").doesNotContain("Segura123");
    }

    @Test
    void email_registered_in_another_organization_rolls_back_the_whole_sign_up() {
        signUp.signUp(command("20123456789", "ana@andina.pe"));

        assertThatThrownBy(() -> signUp.signUp(command("20999999991", "ANA@andina.pe")))
                .isInstanceOf(ConflictException.class)
                .hasFieldOrPropertyWithValue("code", "EMAIL_ALREADY_REGISTERED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM outbox_events", Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM registered_rucs WHERE ruc = '20999999991'",
                Long.class)).isZero();
    }

    @Test
    void registered_ruc_is_a_409() {
        signUp.signUp(command("20123456789", "ana@andina.pe"));

        assertThatThrownBy(() -> signUp.signUp(command("20123456789", "luis@otra.pe")))
                .isInstanceOf(ConflictException.class)
                .hasFieldOrPropertyWithValue("code", "RUC_ALREADY_REGISTERED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM users", Long.class)).isEqualTo(1);
    }

    @Test
    void users_are_filtered_by_organization_but_email_lookup_for_sign_in_sees_all() {
        IamCommandService.SignUpResult andina = signUp.signUp(command("20123456789", "ana@andina.pe"));
        IamCommandService.SignUpResult otra = signUp.signUp(command("20999999991", "luis@otra.pe"));
        TenantInfo andinaAdmin = new TenantInfo(andina.organizationId(), andina.administratorId(), "ADMINISTRATOR");

        List<String> visibleToAndina = TenantContext.callAs(andinaAdmin, () -> tx.execute(status ->
                users.findAll().stream().map(user -> user.email().value()).toList()));
        boolean luisFoundFromAndina = TenantContext.callAs(andinaAdmin, () -> tx.execute(status ->
                users.findByEmail(new EmailAddress("luis@otra.pe")).isPresent()));
        boolean luisExistsAnywhere = TenantContext.callAs(andinaAdmin, () -> tx.execute(status ->
                users.existsByEmailInAnyOrganization(new EmailAddress("luis@otra.pe"))));
        User luisForSignIn = TenantContext.callAsSystem(() -> tx.execute(status ->
                users.findByEmail(new EmailAddress("luis@otra.pe")).orElseThrow()));

        assertThat(visibleToAndina).containsExactly("ana@andina.pe");
        assertThat(luisFoundFromAndina).isFalse();
        assertThat(luisExistsAnywhere).isTrue();
        assertThat(luisForSignIn.organizationId()).isEqualTo(otra.organizationId());
    }

    @Test
    void stale_version_cannot_overwrite_a_user() {
        IamCommandService.SignUpResult andina = signUp.signUp(command("20123456789", "ana@andina.pe"));
        TenantInfo admin = new TenantInfo(andina.organizationId(), andina.administratorId(), "ADMINISTRATOR");
        User loaded = TenantContext.callAs(admin, () -> tx.execute(status -> users.findById(andina.administratorId()).orElseThrow()));
        User stale = User.restore(loaded.id(), loaded.organizationId(), loaded.email(), loaded.fullName(), Role.ADMINISTRATOR,
                loaded.passwordHash(), true, loaded.version());

        TenantContext.runAs(admin, () -> tx.executeWithoutResult(status -> {
            loaded.changePasswordHash("$2a$12$nuevo");
            users.save(loaded);
        }));

        assertThatThrownBy(() -> TenantContext.runAs(admin, () -> tx.executeWithoutResult(status -> {
            stale.changePasswordHash("$2a$12$otro");
            users.save(stale);
        }))).isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
    }

    @Test
    void a_user_cannot_be_created_under_another_organization() {
        IamCommandService.SignUpResult andina = signUp.signUp(command("20123456789", "ana@andina.pe"));
        TenantInfo admin = new TenantInfo(andina.organizationId(), andina.administratorId(), "ADMINISTRATOR");
        User foreign = User.register(UUID.randomUUID(), new EmailAddress("x@otra.pe"), "X", Role.SITE_MANAGER, "h");

        assertThatThrownBy(() -> TenantContext.runAs(admin, () -> tx.executeWithoutResult(status -> users.save(foreign))))
                .hasRootCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("otra organización");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM users WHERE email = 'x@otra.pe'", Long.class)).isZero();
    }

    private static IamCommandService.SignUpCommand command(String ruc, String email) {
        return new IamCommandService.SignUpCommand(ruc, "Constructora " + ruc, "Administrador", email, "Segura123");
    }
}
