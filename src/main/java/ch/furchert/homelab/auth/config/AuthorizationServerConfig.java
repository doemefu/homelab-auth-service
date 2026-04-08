package ch.furchert.homelab.auth.config;

import ch.furchert.homelab.auth.security.OidcUserInfoMapper;
import ch.furchert.homelab.auth.security.RsaKeyProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(OidcClientProperties.class)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private static final String RSA_KEY_ID = "auth-service-v1";

    private final OidcClientProperties oidcClientProperties;
    private final RsaKeyProperties rsaKeyProperties;
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
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/oauth2/**", "/.well-known/**", "/userinfo", "/connect/**")
            .oauth2AuthorizationServer(as -> as
                .oidc(oidc -> oidc
                    .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
                    .providerConfigurationEndpoint(Customizer.withDefaults())
                    .logoutEndpoint(Customizer.withDefaults())
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

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        if (oidcClientProperties.getClients().isEmpty()) {
            throw new IllegalStateException(
                    "No OIDC clients configured. Set app.oidc.clients in application.yaml.");
        }
        List<RegisteredClient> clients = oidcClientProperties.getClients().stream()
                .map(def -> {
                    RegisteredClient.Builder builder = RegisteredClient
                            .withId(UUID.nameUUIDFromBytes(
                                    def.getClientId().getBytes(StandardCharsets.UTF_8)).toString())
                            .clientId(def.getClientId())
                            .clientSecret(def.getClientSecret())
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                            .scopes(scopes -> scopes.addAll(def.getScopes()))
                            .redirectUris(uris -> uris.addAll(def.getRedirectUris()))
                            .clientSettings(ClientSettings.builder()
                                    .requireAuthorizationConsent(false)
                                    .requireProofKey(true)
                                    .build())
                            .tokenSettings(TokenSettings.builder()
                                    .accessTokenTimeToLive(Duration.ofMillis(
                                            rsaKeyProperties.getAccessTokenExpiry()))
                                    .refreshTokenTimeToLive(Duration.ofMillis(
                                            rsaKeyProperties.getRefreshTokenExpiry()))
                                    .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                                    .build());
                    def.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
                    return builder.build();
                })
                .toList();
        return new InMemoryRegisteredClientRepository(clients);
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

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean isIdToken = "id_token".equals(context.getTokenType().getValue());
            if (!isAccessToken && !isIdToken) return;

            context.getPrincipal().getAuthorities().stream()
                    .findFirst()
                    .ifPresent(a -> {
                        String role = a.getAuthority().replaceFirst("^ROLE_", "");
                        context.getClaims().claim("role", role);
                    });
        };
    }
}
