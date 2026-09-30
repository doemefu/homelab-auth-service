package ch.furchert.homelab.auth.config;

import ch.furchert.homelab.auth.security.ClientAuthorizationRequestValidator;
import ch.furchert.homelab.auth.security.OidcUserInfoMapper;
import ch.furchert.homelab.auth.security.ResourceIndicatorPolicy;
import ch.furchert.homelab.auth.security.ResourceIndicatorTokenRequestGuard;
import ch.furchert.homelab.auth.security.RsaKeyProvider;
import ch.furchert.homelab.auth.service.ClientKindLookup;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableConfigurationProperties(OidcClientProperties.class)
@RequiredArgsConstructor
@Slf4j
public class AuthorizationServerConfig {

    private static final String RSA_KEY_ID = "auth-service-v1";

    private final OidcClientProperties oidcClientProperties;
    private final RsaKeyProvider rsaKeyProvider;
    private final OidcUserInfoMapper userInfoMapper;
    private final ClientAuthorizationRequestValidator authorizationRequestValidator;
    private final ResourceIndicatorPolicy resourceIndicatorPolicy;

    /**
     * Chain 1 (AS endpoints): handles OAuth2/OIDC protocol endpoints.
     * Login is handled by chain 2 in SecurityConfig — this chain redirects
     * unauthenticated HTML requests to /login. The shared HTTP session
     * carries authentication state between chains.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/oauth2/**", "/.well-known/**", "/userinfo", "/connect/**")
                .oauth2AuthorizationServer(as -> as
                        .authorizationEndpoint(authorization -> authorization.authenticationProviders(providers ->
                                providers.forEach(provider -> {
                                    if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeRequest) {
                                        // Keep SAS's redirect_uri + scope validation first; per-client rules run after it.
                                        codeRequest.setAuthenticationValidator(
                                                new OAuth2AuthorizationCodeRequestAuthenticationValidator()
                                                        .andThen(authorizationRequestValidator));
                                    }
                                })))
                        // Constructed here, never a bean: an AuthenticationConverter bean would replace the
                        // bearer-token converter of every resource-server chain (see the guard's Javadoc).
                        .tokenEndpoint(token -> token.accessTokenRequestConverters(converters ->
                                converters.addFirst(new ResourceIndicatorTokenRequestGuard(
                                        oidcClientProperties, resourceIndicatorPolicy))))
                        .oidc(oidc -> oidc
                                .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
                                .providerConfigurationEndpoint(Customizer.withDefaults())
                                .logoutEndpoint(logout -> logout.errorResponseHandler(oidcLogoutErrorResponseHandler()))
                        )
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    /**
     * RP-initiated logout ({@code /connect/logout}) requires an {@code id_token_hint}
     * that resolves to a stored {@code oauth2_authorization} row. That lookup fails
     * once the authorization has been purged by {@link ch.furchert.homelab.auth.service.TokenCleanupScheduler}
     * (roughly the refresh-token TTL — 7 days — after login) or when the ID token was
     * issued to a different browser session ({@code sid} mismatch). Spring Authorization
     * Server's default handler turns that into a bare {@code 400 invalid_token} error
     * page and leaves the IdP's own session alive.
     * <p>
     * Ending the local session on <em>any</em> logout failure would turn this GET endpoint
     * into a cross-site forced-logout link — e.g. {@code <img src="/connect/logout?id_token_hint=garbage">}
     * embedded on an unrelated site would log the victim out, regardless of whether
     * {@code id_token_hint} ever belonged to them. To close that hole, the local session is
     * only ended when the hint is a JWT whose <em>signature</em> verifies against this
     * server's own signing key ({@link #idTokenHintSignatureDecoder()}) — proof
     * that it was genuinely issued by this IdP to some past RP session, even though the
     * lookup above failed. Only the signature is checked (no timestamp/issuer validation):
     * an expired or already-purged hint is still evidence of a legitimate former session
     * and must still end it, matching the resolvable-hint success path. A forged or
     * garbage hint cannot produce a valid signature and falls back to the standard
     * behavior — {@code response.sendError(400, ...)} — leaving the IdP's session
     * untouched.
     * <p>
     * The redirect target is fixed to {@code /login?logout} rather than the client's
     * requested {@code post_logout_redirect_uri}: that URI can only be validated against
     * the registered client once the {@code id_token_hint} has resolved, so honoring it
     * here would be an open redirect.
     */
    private AuthenticationFailureHandler oidcLogoutErrorResponseHandler() {
        JwtDecoder idTokenHintSignatureDecoder = idTokenHintSignatureDecoder();
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) -> {
            String hint = request.getParameter("id_token_hint");
            boolean genuine = false;
            if (hint != null && !hint.isBlank()) {
                try {
                    idTokenHintSignatureDecoder.decode(hint);
                    genuine = true;
                } catch (JwtException e) {
                    genuine = false;
                }
            }

            if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
                OAuth2Error error = oauth2Exception.getError();
                log.warn("OIDC logout rejected: {} ({}) — {}", error.getErrorCode(), error.getDescription(),
                        genuine ? "server-signed id_token_hint, performing local logout"
                                : "id_token_hint not verifiable, returning standard error response");
            }

            if (genuine) {
                new SecurityContextLogoutHandler().logout(request, response,
                        SecurityContextHolder.getContext().getAuthentication());
                response.sendRedirect("/login?logout");
            } else if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
                response.sendError(HttpStatus.BAD_REQUEST.value(), oauth2Exception.getError().toString());
            } else {
                response.sendError(HttpStatus.BAD_REQUEST.value());
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyProvider.getPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyProvider.getPrivateKey();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(RSA_KEY_ID)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /**
     * Signature-only decoder used exclusively by {@link #oidcLogoutErrorResponseHandler()}
     * to check whether an {@code id_token_hint} was genuinely signed by this server. Timestamp
     * and issuer validation are intentionally disabled ({@code setJwtValidator} always succeeds):
     * this decoder's only job is proving provenance (a valid signature), not token freshness —
     * an expired or already-purged token must still pass here so the handler can distinguish it
     * from a forged/garbage hint. Never used to authenticate or authorize a request.
     * <p>
     * Deliberately <em>not</em> a {@code @Bean}: {@code SecurityConfig}'s resource-server
     * chain auto-discovers a {@code JwtDecoder} bean by type for access-token validation, and
     * a second bean of that type there would make that lookup ambiguous. This decoder is only
     * ever built once, from {@link #authorizationServerSecurityFilterChain(HttpSecurity)}
     * (a singleton {@code @Bean} method invoked once at startup), and captured in the
     * returned handler's closure.
     */
    private JwtDecoder idTokenHintSignatureDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource()).build();
        decoder.setJwtValidator(token -> OAuth2TokenValidatorResult.success());
        return decoder;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * JDBC-backed registered-client repository. SSO clients are seeded from
     * application.yaml on first boot by {@link StaticClientSeeder}; device
     * clients are created via the admin API. An empty DB on boot is valid:
     * the seeder will populate it.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
        return new JdbcRegisteredClientRepository(jdbcOperations);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(oidcClientProperties.getIssuer())
                .build();
    }

    /**
     * Adds JWT claims:
     * <ul>
     *   <li>{@code role}: stripped of the ROLE_ prefix, taken from the principal's first
     *       authority. Only fires for user-driven grants (auth_code).</li>
     *   <li>{@code device_id}: the clientId of the registered client, added ONLY for
     *       client_credentials access tokens whose client_kind = 'device'. Mosquitto's
     *       JWT plugin uses this for MQTT ACL evaluation.</li>
     *   <li>audience-bound clients ({@code access-token-audience}): access tokens of user-driven
     *       grants get header {@code typ: at+jwt}, {@code aud} = [configured audience] and a
     *       {@code client_id} claim, and no {@code role} or {@code device_id} (docs/080 §4.2).</li>
     * </ul>
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(ClientKindLookup clientKindLookup) {
        return context -> {
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean isIdToken = "id_token".equals(context.getTokenType().getValue());
            if (!isAccessToken && !isIdToken) return;

            // Audience-bound clients (docs/080 §4.2): tokens for one resource server only. Limited to
            // user-driven grants, so a device client that happens to share the client_id is unaffected.
            // Fail closed (#107): a row seeded as audience-bound never falls back to the default shape.
            // The token-request guard refuses such a client first; this is the last line of defence.
            if (oidcClientProperties.isAudienceBoundWithoutDefinition(context.getRegisteredClient())) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "This client is not configured", null));
            }
            AuthorizationGrantType grant = context.getAuthorizationGrantType();
            String clientId = context.getRegisteredClient().getClientId();
            String audience = oidcClientProperties.findClient(clientId)
                    .map(OidcClientProperties.ClientDefinition::getAccessTokenAudience)
                    .filter(a -> !a.isBlank())
                    .orElse(null);
            if (isAccessToken && audience != null
                    && (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grant)
                        || AuthorizationGrantType.REFRESH_TOKEN.equals(grant))) {
                context.getJwsHeader().type("at+jwt");
                // Mutable list on purpose: the claims are stored with the authorization as typed JSON and
                // read back on every refresh; the store's Jackson allowlist rejects JDK immutable lists.
                context.getClaims().audience(new ArrayList<>(List.of(audience)));
                context.getClaims().claim("client_id", clientId);
                return; // no role, no device_id
            }

            // role claim — only emit for ROLE_* authorities (user-driven grants)
            context.getPrincipal().getAuthorities().stream()
                    .filter(a -> a.getAuthority().startsWith("ROLE_"))
                    .findFirst()
                    .ifPresent(a -> {
                        String role = a.getAuthority().replaceFirst("^ROLE_", "");
                        context.getClaims().claim("role", role);
                    });

            // device_id claim — client_credentials access tokens for device clients
            if (isAccessToken
                    && AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())
                    && clientKindLookup.isDevice(context.getRegisteredClient().getId())) {
                context.getClaims().claim("device_id", context.getRegisteredClient().getClientId());
            }
        };
    }
}
