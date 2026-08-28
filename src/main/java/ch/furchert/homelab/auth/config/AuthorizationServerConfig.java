package ch.furchert.homelab.auth.config;

import ch.furchert.homelab.auth.security.OidcUserInfoMapper;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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

@Configuration
@EnableConfigurationProperties(OidcClientProperties.class)
@RequiredArgsConstructor
@Slf4j
public class AuthorizationServerConfig {

    private static final String RSA_KEY_ID = "auth-service-v1";

    private final OidcClientProperties oidcClientProperties;
    private final RsaKeyProvider rsaKeyProvider;
    private final OidcUserInfoMapper userInfoMapper;

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
     * page and leaves the IdP's own session alive. Instead, end the local session and
     * send the user back to the login page.
     * <p>
     * The redirect target is fixed to {@code /login?logout} rather than the client's
     * requested {@code post_logout_redirect_uri}: that URI can only be validated against
     * the registered client once the {@code id_token_hint} has resolved, so honoring it
     * here would be an open redirect.
     */
    private AuthenticationFailureHandler oidcLogoutErrorResponseHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) -> {
            if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
                OAuth2Error error = oauth2Exception.getError();
                log.warn("OIDC logout rejected: {} ({}) — performing local logout",
                        error.getErrorCode(), error.getDescription());
            }
            new SecurityContextLogoutHandler().logout(request, response,
                    SecurityContextHolder.getContext().getAuthentication());
            response.sendRedirect("/login?logout");
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
     * </ul>
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(ClientKindLookup clientKindLookup) {
        return context -> {
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean isIdToken = "id_token".equals(context.getTokenType().getValue());
            if (!isAccessToken && !isIdToken) return;

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
