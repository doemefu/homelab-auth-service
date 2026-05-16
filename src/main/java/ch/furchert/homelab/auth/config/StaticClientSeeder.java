package ch.furchert.homelab.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

/**
 * Seeds the SSO clients from application.yaml into oauth2_registered_client on
 * startup, AFTER Flyway has run and BEFORE HTTP traffic is served. Idempotent:
 * each client is skipped if it already exists (by client_id). YAML is therefore
 * a bootstrap source only — post-bootstrap edits must go through psql or the
 * (future) admin API.
 * <p>
 * client_kind: seeded rows inherit {@code 'sso'} from the V5 column default —
 * no explicit write here. Device clients set {@code 'device'} via a side-write
 * in {@code DeviceClientService}.
 * <p>
 * Secret handling: YAML values are passed through verbatim — they MUST already
 * carry a DelegatingPasswordEncoder prefix ({noop}/{bcrypt}/...) per the
 * application.yaml comment on each client. Re-encoding a {bcrypt} value would
 * double-hash and silently break SSO logins.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class StaticClientSeeder implements ApplicationRunner {

    private final OidcClientProperties properties;
    private final RsaKeyProperties rsaKeyProperties;
    private final RegisteredClientRepository registeredClientRepository;
    private final JdbcTemplate jdbcTemplate;

    @Override
    public void run(@NonNull ApplicationArguments args) {
        int seeded = 0;
        for (OidcClientProperties.ClientDefinition def : properties.getClients()) {
            if (registeredClientRepository.findByClientId(def.getClientId()) != null) {
                log.debug("SSO client '{}' already present in DB; skipping seed", def.getClientId());
                continue;
            }
            RegisteredClient client = buildRegisteredClient(def);
            registeredClientRepository.save(client);
            seeded++;
            log.info("Seeded SSO client '{}' (id={})", def.getClientId(), client.getId());
        }

        Integer total = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client", Integer.class);
        long totalCount = total == null ? 0L : total;
        if (totalCount == 0) {
            log.warn("No clients in oauth2_registered_client after seeding — "
                    + "this auth-service instance cannot serve any OAuth2 flow");
        } else {
            log.info("StaticClientSeeder finished: seeded {} new clients of {} configured; total in DB: {}",
                    seeded, properties.getClients().size(), totalCount);
        }
    }

    private RegisteredClient buildRegisteredClient(OidcClientProperties.ClientDefinition def) {
        RegisteredClient.Builder builder = RegisteredClient
                .withId(UUID.nameUUIDFromBytes(
                        def.getClientId().getBytes(StandardCharsets.UTF_8)).toString())
                .clientId(def.getClientId())
                .clientSecret(def.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scopes(scopes -> scopes.addAll(def.getScopes()))
                .redirectUris(uris -> uris.addAll(def.getRedirectUris()))
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMillis(rsaKeyProperties.getAccessTokenExpiry()))
                        .refreshTokenTimeToLive(Duration.ofMillis(rsaKeyProperties.getRefreshTokenExpiry()))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                        .build());

        for (String grant : def.getGrantTypes()) {
            builder.authorizationGrantType(new AuthorizationGrantType(grant));
        }
        def.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        return builder.build();
    }
}
