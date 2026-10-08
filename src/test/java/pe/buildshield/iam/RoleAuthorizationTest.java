package pe.buildshield.iam;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import pe.buildshield.iam.shared.security.JwtTokenIssuer;
import pe.buildshield.iam.shared.security.RevokedTokenStore;
import pe.buildshield.iam.shared.tenant.TenantInfo;
import pe.buildshield.iam.application.AuthenticationService;
import pe.buildshield.iam.application.PasswordResetService;
import pe.buildshield.iam.application.IamCommandService;
import pe.buildshield.iam.application.IamQueryService;
import pe.buildshield.iam.application.UserView;
import pe.buildshield.iam.domain.model.Role;
import pe.buildshield.iam.support.WebSliceTest;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Matriz de autorización de toda la API de iam: cada endpoint contra usuario anónimo y cada rol
 * (los servicios están simulados). Además verifica que ningún endpoint quede sin una regla explícita
 * de {@code @PreAuthorize}.
 */
@WebMvcTest
@WebSliceTest
class RoleAuthorizationTest {

    private static final UUID ANY_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");

    private static final Map<String, String> BODIES = Map.ofEntries(
            Map.entry("sign-up", "{\"ruc\":\"20123456789\",\"legalName\":\"Andina\",\"adminFullName\":\"Ana\",\"adminEmail\":\"ana@andina.pe\",\"password\":\"Segura123\"}"),
            Map.entry("sign-in", "{\"email\":\"ana@andina.pe\",\"password\":\"Segura123\"}"),
            Map.entry("refresh", "{\"refreshToken\":\"abc\"}"),
            Map.entry("sign-out", "{\"refreshToken\":\"abc\"}"),
            Map.entry("reset", "{\"email\":\"ana@andina.pe\"}"),
            Map.entry("reset-confirm", "{\"token\":\"abc\",\"newPassword\":\"Nueva12345\"}"),
            Map.entry("update-user", "{\"active\":false}"),
            Map.entry("create-user", "{\"fullName\":\"Rosa\",\"email\":\"rosa@andina.pe\",\"role\":\"WAREHOUSE_MANAGER\",\"password\":\"Almacen123\"}"));

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtTokenIssuer issuer;

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    RequestMappingHandlerMapping handlerMapping;

    @MockitoBean
    RevokedTokenStore revokedTokens;

    @MockitoBean
    IamCommandService commands;

    @MockitoBean
    IamQueryService queries;

    @MockitoBean
    PasswordResetService passwordResetService;

    @MockitoBean
    AuthenticationService authenticationService;

    @BeforeEach
    void stubServices() {
        when(commands.signUp(any())).thenReturn(new IamCommandService.SignUpResult(UUID.randomUUID(), UUID.randomUUID()));
        AuthenticationService.SessionTokens tokens = new AuthenticationService.SessionTokens("a", Instant.now(), "r", Instant.now());
        when(authenticationService.signIn(anyString(), anyString())).thenReturn(tokens);
        when(authenticationService.refresh(anyString())).thenReturn(tokens);
        when(commands.createUser(any())).thenReturn(new UserView(
                UUID.randomUUID(), "rosa@andina.pe", "Rosa", Role.WAREHOUSE_MANAGER, true));
        when(queries.listUsers()).thenReturn(List.of());
        when(commands.updateUser(any(), any())).thenReturn(new UserView(
                ANY_ID, "rosa@andina.pe", "Rosa", Role.WAREHOUSE_MANAGER, false));
    }

    @ParameterizedTest(name = "{0} {1} como {2} -> {3}")
    @CsvSource({
            // endpoint              , cuerpo     , quién             , estado
            "POST, /api/v1/auth/sign-up , sign-up    , ANONYMOUS        , 201",
            "POST, /api/v1/auth/sign-in , sign-in    , ANONYMOUS        , 200",
            "POST, /api/v1/auth/refresh , refresh    , ANONYMOUS        , 200",
            "POST, /api/v1/auth/password-reset        , reset        , ANONYMOUS, 202",
            "POST, /api/v1/auth/password-reset/confirm, reset-confirm, ANONYMOUS, 204",
            "POST, /api/v1/auth/sign-out, sign-out   , ANONYMOUS        , 401",
            "POST, /api/v1/auth/sign-out, sign-out   , ADMINISTRATOR    , 204",
            "POST, /api/v1/auth/sign-out, sign-out   , WAREHOUSE_MANAGER, 204",
            "POST, /api/v1/auth/sign-out, sign-out   , SITE_MANAGER     , 204",
            "POST, /api/v1/users        , create-user, ANONYMOUS        , 401",
            "POST, /api/v1/users        , create-user, ADMINISTRATOR    , 201",
            "POST, /api/v1/users        , create-user, WAREHOUSE_MANAGER, 403",
            "POST, /api/v1/users        , create-user, SITE_MANAGER     , 403",
            "GET , /api/v1/users        ,            , ANONYMOUS        , 401",
            "GET , /api/v1/users        ,            , ADMINISTRATOR    , 200",
            "GET , /api/v1/users        ,            , WAREHOUSE_MANAGER, 403",
            "GET , /api/v1/users        ,            , SITE_MANAGER     , 403",
            "PATCH, /api/v1/users/00000000-0000-0000-0000-0000000000bb, update-user, ANONYMOUS, 401",
            "PATCH, /api/v1/users/00000000-0000-0000-0000-0000000000bb, update-user, ADMINISTRATOR, 200",
            "PATCH, /api/v1/users/00000000-0000-0000-0000-0000000000bb, update-user, WAREHOUSE_MANAGER, 403",
            "PATCH, /api/v1/users/00000000-0000-0000-0000-0000000000bb, update-user, SITE_MANAGER, 403",
    })
    void endpoint_is_allowed_only_for_its_roles(String method, String path, String body, String who, int expectedStatus)
            throws Exception {
        MockHttpServletRequestBuilder request = switch (method) {
            case "GET" -> get(path);
            case "PATCH" -> patch(path);
            default -> post(path);
        };
        if (body != null) {
            request.contentType(MediaType.APPLICATION_JSON).content(BODIES.get(body));
        }
        if (!"ANONYMOUS".equals(who)) {
            String token = issuer.issue(new TenantInfo(UUID.randomUUID(), UUID.randomUUID(), who)).value();
            request.header("Authorization", "Bearer " + token);
        }

        mvc.perform(request).andExpect(status().is(expectedStatus));
    }

    @Test
    void every_endpoint_declares_its_authorization_rule() {
        List<String> withoutRule = handlerMapping.getHandlerMethods().values().stream()
                .filter(handler -> handler.getBeanType().getPackageName().startsWith("pe.buildshield.iam"))
                .filter(handler -> !hasPreAuthorize(handler))
                .map(handler -> handler.getBeanType().getSimpleName() + "#" + handler.getMethod().getName())
                .toList();

        assertThat(handlerMapping.getHandlerMethods()).isNotEmpty();
        assertThat(withoutRule).as("endpoints sin @PreAuthorize").isEmpty();
    }

    private static boolean hasPreAuthorize(HandlerMethod handler) {
        return handler.hasMethodAnnotation(PreAuthorize.class)
                || handler.getBeanType().isAnnotationPresent(PreAuthorize.class);
    }
}
