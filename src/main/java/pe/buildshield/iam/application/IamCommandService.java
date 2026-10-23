package pe.buildshield.iam.application;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import pe.buildshield.iam.domain.model.AuthenticationFailedException;
import pe.buildshield.iam.domain.model.EmailAddress;
import pe.buildshield.iam.domain.model.PasswordResetToken;
import pe.buildshield.iam.domain.model.RefreshToken;
import pe.buildshield.iam.domain.model.TokenRepositories.AccessTokenBlocklist;
import pe.buildshield.iam.domain.model.TokenRepositories.PasswordResetTokenRepository;
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
import pe.buildshield.iam.shared.security.BuildshieldJwt;
import pe.buildshield.iam.shared.security.JwtTokenProvider;
import pe.buildshield.iam.shared.tenant.TenantContext;
import pe.buildshield.iam.shared.tenant.TenantInfo;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

/**
 * IAM CommandService del C4 (pág. 27 de la v4): registro, inicio y cierre de sesión, recuperación y cambio
 * de contraseña y gestión de usuarios y roles. Son los casos de uso de iam que cambian estado. Cada cambio se guarda junto con su evento de integración en
 * el outbox, en la misma transacción:
 *
 * <ul>
 *   <li>US01: alta de la organización y su administrador ({@code OrganizationRegistered} y {@code UserCreated}).</li>
 *   <li>US04: el administrador crea usuarios ({@code UserCreated}), los desactiva, reactiva y les cambia el
 *       rol ({@code UserUpdated}). La restricción de rol está en el controlador; aquí todo queda acotado a la
 *       organización del contexto.</li>
 *   <li>US02 y US03: inicio de sesión, renovación con rotación del token de renovación y cierre de sesión con
 *       revocación del token de acceso hasta que venza.</li>
 *   <li>US05: recuperación de contraseña ({@code PasswordResetRequested}; el correo lo envía Notificaciones).</li>
 *   <li>Modo de acceso de la organización ({@code organization_access}), que llega por eventos de Suscripción.</li>
 * </ul>
 */
@Service
public class IamCommandService {

    public static final String CANNOT_CHANGE_OWN_ACCOUNT = "CANNOT_CHANGE_OWN_ACCOUNT";

    private static final Logger log = LoggerFactory.getLogger(IamCommandService.class);

    private final UserRepository users;
    private final RegisteredRucRepository rucs;
    private final OrganizationAccessRepository organizationAccess;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final AccessTokenBlocklist accessTokenBlocklist;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final TransactionTemplate transactionTemplate;
    private final OutboxWriter outbox;
    private final Clock clock;
    private final IamProperties properties;
    private volatile String unknownUserHash;

    public IamCommandService(UserRepository users, RegisteredRucRepository rucs,
            OrganizationAccessRepository organizationAccess, RefreshTokenRepository refreshTokens,
            PasswordResetTokenRepository resetTokens, AccessTokenBlocklist accessTokenBlocklist,
            JwtTokenProvider jwtTokenProvider, PasswordEncoder passwordEncoder, TransactionTemplate transactionTemplate,
            OutboxWriter outbox, Clock clock, IamProperties properties) {
        this.users = users;
        this.rucs = rucs;
        this.organizationAccess = organizationAccess;
        this.refreshTokens = refreshTokens;
        this.resetTokens = resetTokens;
        this.accessTokenBlocklist = accessTokenBlocklist;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.transactionTemplate = transactionTemplate;
        this.outbox = outbox;
        this.clock = clock;
        this.properties = properties;
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

    /** US02: inicio de sesión. */
    public SessionTokens signIn(String rawEmail, String password) {
        Optional<EmailAddress> email = parseEmail(rawEmail);
        // Aún no hay organización: se busca el correo en todas (modo sistema, solo lectura).
        Optional<User> user = email.flatMap(address ->
                TenantContext.callAsSystem(() -> transactionTemplate.execute(status -> users.findByEmail(address))));

        // Se compara siempre con bcrypt, exista o no el usuario, para no revelar por el tiempo de
        // respuesta qué correos están registrados.
        String hash = user.map(User::passwordHash).orElseGet(this::unknownUserHash);
        boolean matches = passwordEncoder.matches(password == null ? "" : password, hash);
        if (user.isEmpty() || !matches || !user.get().canSignIn()) {
            throw AuthenticationFailedException.invalidCredentials();
        }
        return openSession(user.get());
    }

    public SessionTokens refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw AuthenticationFailedException.invalidRefreshToken();
        }
        String nextRawToken = OpaqueTokens.newToken();
        Instant now = clock.instant();
        Rotation rotation = TenantContext.callAsSystem(() -> transactionTemplate.execute(status -> {
            RefreshToken current = refreshTokens.findByTokenHashForUpdate(OpaqueTokens.hash(rawRefreshToken))
                    .orElseThrow(AuthenticationFailedException::invalidRefreshToken);
            RefreshToken next = current.rotate(OpaqueTokens.hash(nextRawToken), now, properties.refreshTokenTtl());
            User user = users.findById(current.userId())
                    .filter(User::canSignIn)
                    .orElseThrow(AuthenticationFailedException::invalidRefreshToken);
            refreshTokens.save(current);
            refreshTokens.save(next);
            return new Rotation(user, next);
        }));
        return sessionTokens(rotation.user(), nextRawToken, rotation.next());
    }

    /**
     * Revoca el token de renovación (si es del usuario) y registra el token de acceso en la lista de
     * revocación hasta su vencimiento. Se ejecuta con la organización del token.
     */
    public void signOut(UUID userId, String accessTokenId, String rawRefreshToken) {
        Instant now = clock.instant();
        transactionTemplate.executeWithoutResult(status -> {
            if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
                refreshTokens.findByTokenHashForUpdate(OpaqueTokens.hash(rawRefreshToken))
                        .filter(token -> token.userId().equals(userId))
                        .ifPresent(token -> {
                            token.revoke(now);
                            refreshTokens.save(token);
                        });
            }
            accessTokenBlocklist.block(accessTokenId,
                    now.plus(BuildshieldJwt.TOKEN_LIFETIME).plus(BuildshieldJwt.CLOCK_SKEW));
        });
    }

    private SessionTokens openSession(User user) {
        String rawRefreshToken = OpaqueTokens.newToken();
        RefreshToken refreshToken = RefreshToken.issue(user.id(), user.organizationId(),
                OpaqueTokens.hash(rawRefreshToken), clock.instant(), properties.refreshTokenTtl());
        TenantContext.runAsSystem(() -> transactionTemplate.executeWithoutResult(status -> refreshTokens.save(refreshToken)));
        return sessionTokens(user, rawRefreshToken, refreshToken);
    }

    private SessionTokens sessionTokens(User user, String rawRefreshToken, RefreshToken refreshToken) {
        JwtTokenProvider.IssuedToken access = jwtTokenProvider.issue(
                new TenantInfo(user.organizationId(), user.id(), user.role().name()));
        // El claim exp del JWT va en segundos: se informa el mismo instante que valida el servidor.
        return new SessionTokens(access.value(), access.expiresAt().truncatedTo(ChronoUnit.SECONDS),
                rawRefreshToken, refreshToken.expiresAt());
    }

    private static Optional<EmailAddress> parseEmail(String rawEmail) {
        try {
            return Optional.of(new EmailAddress(rawEmail));
        } catch (ValidationException ex) {
            return Optional.empty();
        }
    }

    private String unknownUserHash() {
        if (unknownUserHash == null) {
            unknownUserHash = passwordEncoder.encode(UUID.randomUUID().toString());
        }
        return unknownUserHash;
    }

    /**
     * US05: recuperación de contraseña con un enlace de un solo uso que vence. La solicitud responde igual
     * exista o no el correo, para no revelar qué correos están registrados.
     */
    public void requestReset(String rawEmail) {
        Optional<User> user = parseEmail(rawEmail).flatMap(address ->
                TenantContext.callAsSystem(() -> transactionTemplate.execute(status -> users.findByEmail(address))))
                .filter(User::canSignIn);
        if (user.isEmpty()) {
            log.info("Solicitud de recuperación de contraseña para un correo no registrado o inactivo");
            return;
        }
        String rawToken = OpaqueTokens.newToken();
        PasswordResetToken token = PasswordResetToken.issue(user.get().id(), user.get().organizationId(),
                OpaqueTokens.hash(rawToken), clock.instant(), properties.passwordResetTtl());
        User requester = user.get();
        // Notificaciones envía el correo al consumir PasswordResetRequested (SendGrid): iam no habla con el proveedor.
        TenantContext.runAsSystem(() -> transactionTemplate.executeWithoutResult(status -> {
            resetTokens.save(token);
            outbox.append(requester.organizationId(), null, IamEvents.PASSWORD_RESET_REQUESTED, IamEvents.USER,
                    requester.id(), new IamEvents.PasswordResetRequested(requester.id(), requester.email().value(),
                            requester.fullName(), properties.passwordResetUrl() + "?token=" + rawToken,
                            token.expiresAt()));
        }));
    }

    /** Cambia la contraseña, invalida el enlace y cierra las sesiones renovables del usuario. */
    public void confirmReset(String rawToken, String newPassword) {
        PasswordPolicy.validate(newPassword, "newPassword");
        if (rawToken == null || rawToken.isBlank()) {
            throw PasswordResetToken.invalid();
        }
        String newHash = passwordEncoder.encode(newPassword);
        Instant now = clock.instant();
        TenantContext.runAsSystem(() -> transactionTemplate.executeWithoutResult(status -> {
            PasswordResetToken token = resetTokens.findByTokenHashForUpdate(OpaqueTokens.hash(rawToken))
                    .orElseThrow(PasswordResetToken::invalid);
            token.use(now);
            User user = users.findById(token.userId()).orElseThrow(PasswordResetToken::invalid);
            user.changePasswordHash(newHash);
            users.save(user);
            resetTokens.save(token);
            refreshTokens.revokeAllActive(user.id(), now);
        }));
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

    public record SessionTokens(String accessToken, Instant accessTokenExpiresAt, String refreshToken,
            Instant refreshTokenExpiresAt) {
    }

    private record Rotation(User user, RefreshToken next) {
    }
}
