package pe.buildshield.iam.application;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.OrganizationAccess;
import pe.buildshield.iam.domain.model.OrganizationAccessRepository;
import pe.buildshield.iam.domain.model.OrganizationRegistration;
import pe.buildshield.iam.domain.model.PasswordPolicy;
import pe.buildshield.iam.domain.model.RegisteredRucRepository;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.domain.model.TokenRepositories.RefreshTokenRepository;
import pe.buildshield.iam.domain.model.User;
import pe.buildshield.iam.domain.model.UserRepository;
import pe.buildshield.iam.shared.error.ConflictException;
import pe.buildshield.iam.shared.error.ForbiddenException;
import pe.buildshield.iam.shared.error.ResourceNotFoundException;
import pe.buildshield.iam.shared.error.ValidationException;
import pe.buildshield.iam.shared.messaging.OutboxWriter;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;

import java.time.Clock;
import java.util.UUID;

/**
 * Casos de uso de iam que cambian estado. Cada cambio se guarda junto con su evento de integración en
 * el outbox, en la misma transacción:
 *
 * <ul>
 *   <li>US01: alta de la organización y su administrador ({@code OrganizationRegistered} y {@code UserCreated}).</li>
 *   <li>US04: el administrador crea usuarios ({@code UserCreated}), los desactiva, reactiva y les cambia el
 *       rol ({@code UserUpdated}). La restricción de rol está en el controlador; aquí todo queda acotado a la
 *       organización del contexto.</li>
 *   <li>Estado de la suscripción ({@code organization_access}), que llega por eventos de Suscripción.</li>
 * </ul>
 */
@Service
public class IamCommandService {

    public static final String CANNOT_CHANGE_OWN_ACCOUNT = "CANNOT_CHANGE_OWN_ACCOUNT";

    private final UserRepository users;
    private final RegisteredRucRepository rucs;
    private final OrganizationAccessRepository organizationAccess;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final TransactionTemplate transactionTemplate;
    private final OutboxWriter outbox;
    private final Clock clock;

    public IamCommandService(UserRepository users, RegisteredRucRepository rucs,
            OrganizationAccessRepository organizationAccess, RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder, TransactionTemplate transactionTemplate, OutboxWriter outbox, Clock clock) {
        this.users = users;
        this.rucs = rucs;
        this.organizationAccess = organizationAccess;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.transactionTemplate = transactionTemplate;
        this.outbox = outbox;
        this.clock = clock;
    }

    /**
     * US01: registra la organización y su administrador en una sola transacción. Si algo falla (RUC o
     * correo repetidos), no queda nada registrado ni se publica ningún evento.
     */
    public SignUpResult signUp(SignUpCommand command) {
        EmailAddress email = new EmailAddress(command.adminEmail());
        PasswordPolicy.validate(command.password(), "password");
        UUID organizationId = UUID.randomUUID();
        OrganizationRegistration registration = OrganizationRegistration.of(organizationId, command.ruc(),
                command.legalName());
        String passwordHash = passwordEncoder.encode(command.password());

        // La organización aún no existe: se abre la transacción en su nombre para que el filtro
        // multiempresa asigne su id al administrador.
        TenantInfo registering = new TenantInfo(organizationId, TenantContext.SYSTEM_USER_ID, Role.ADMINISTRATOR.name());
        try {
            return TenantContext.callAs(registering, () -> transactionTemplate.execute(status -> {
                if (rucs.exists(registration.ruc())) {
                    throw UniqueConstraints.rucAlreadyRegistered(registration.ruc().value());
                }
                rucs.register(registration.ruc(), organizationId);
                if (users.existsByEmailInAnyOrganization(email)) {
                    throw UniqueConstraints.emailAlreadyRegistered();
                }
                User administrator = users.save(User.register(organizationId, email, command.adminFullName(),
                        Role.ADMINISTRATOR, passwordHash));
                organizationAccess.save(OrganizationAccess.trial(organizationId));
                outbox.append(organizationId, administrator.id(), IamEvents.ORGANIZATION_REGISTERED,
                        IamEvents.ORGANIZATION, organizationId, new IamEvents.OrganizationRegistered(organizationId,
                                registration.ruc().value(), registration.legalName(), administrator.id(),
                                administrator.email().value(), administrator.fullName()));
                outbox.append(organizationId, administrator.id(), IamEvents.USER_CREATED, IamEvents.USER,
                        administrator.id(), userCreated(administrator));
                return new SignUpResult(organizationId, administrator.id());
            }));
        } catch (DataIntegrityViolationException ex) {
            throw UniqueConstraints.translate(ex);
        }
    }

    @Transactional
    public UserView createUser(CreateUserCommand command) {
        EmailAddress email = new EmailAddress(command.email());
        Role role = Role.parse(command.role());
        PasswordPolicy.validate(command.password(), "password");
        UUID organizationId = TenantContext.require().organizationId();
        requireWritable(organizationId);
        if (users.existsByEmailInAnyOrganization(email)) {
            throw UniqueConstraints.emailAlreadyRegistered();
        }
        try {
            User created = users.save(User.register(organizationId, email, command.fullName(), role,
                    passwordEncoder.encode(command.password())));
            outbox.append(IamEvents.USER_CREATED, IamEvents.USER, created.id(), userCreated(created));
            return UserView.of(created);
        } catch (DataIntegrityViolationException ex) {
            throw UniqueConstraints.translate(ex);
        }
    }

    /**
     * US04: desactiva o reactiva al usuario y cambia su rol. El administrador no se desactiva ni cambia su
     * propio rol (409). Si algo cambia, revoca sus sesiones renovables y publica {@code UserUpdated}: sus
     * tokens de acceso dejan de valer en iam (el filtro JWT compara el rol y el estado actuales) y en los
     * servicios que guardan la copia del usuario.
     */
    @Transactional
    public UserView updateUser(UUID userId, UpdateUserCommand command) {
        if (command.active() == null && (command.role() == null || command.role().isBlank())) {
            throw new ValidationException("EMPTY_UPDATE", "Indica active o role");
        }
        Role role = command.role() == null ? null : Role.parse(command.role());
        TenantInfo requester = TenantContext.require();
        User user = users.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("USER_NOT_FOUND", "El usuario " + userId + " no existe"));
        if (user.id().equals(requester.userId())
                && (Boolean.FALSE.equals(command.active()) || (role != null && role != user.role()))) {
            throw new ConflictException(CANNOT_CHANGE_OWN_ACCOUNT,
                    "No puedes desactivarte ni cambiar tu propio rol; pídelo a otro administrador");
        }
        requireWritable(requester.organizationId());
        if (!user.update(command.active(), role)) {
            return UserView.of(user);
        }
        User saved = users.save(user);
        refreshTokens.revokeAllActive(saved.id(), clock.instant());
        outbox.append(IamEvents.USER_UPDATED, IamEvents.USER, saved.id(), new IamEvents.UserUpdated(saved.id(),
                saved.fullName(), saved.email().value(), saved.role().name(), saved.active()));
        return UserView.of(saved);
    }

    /** Estado de la suscripción informado por Suscripción y Pagos. Corre dentro del consumidor idempotente. */
    @Transactional
    public void applySubscriptionStatus(OrganizationAccess access) {
        organizationAccess.save(access);
    }

    /** Con la suscripción vencida, la cuenta queda en solo lectura: no se crean ni cambian usuarios. */
    private void requireWritable(UUID organizationId) {
        organizationAccess.find(organizationId).filter(OrganizationAccess::isReadOnly).ifPresent(access -> {
            throw new ForbiddenException(OrganizationAccess.SUBSCRIPTION_READ_ONLY,
                    "La suscripción de la organización venció: la cuenta está en solo lectura hasta renovar el pago");
        });
    }

    private static IamEvents.UserCreated userCreated(User user) {
        return new IamEvents.UserCreated(user.id(), user.fullName(), user.email().value(), user.role().name(),
                user.active());
    }

    public record SignUpCommand(String ruc, String legalName, String adminFullName, String adminEmail, String password) {
    }

    public record SignUpResult(UUID organizationId, UUID administratorId) {
    }

    public record CreateUserCommand(String fullName, String email, String role, String password) {
    }

    public record UpdateUserCommand(Boolean active, String role) {
    }
}
