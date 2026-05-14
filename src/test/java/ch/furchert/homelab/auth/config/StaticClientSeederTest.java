package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StaticClientSeederTest {

    @Mock
    RegisteredClientRepository repo;
    @Mock
    JdbcTemplate jdbcTemplate;

    private OidcClientProperties props;
    private RsaKeyProperties rsaKeyProperties;
    private StaticClientSeeder seeder;

    @BeforeEach
    void setUp() {
        props = new OidcClientProperties();
        props.setIssuer("https://auth.test");
        rsaKeyProperties = new RsaKeyProperties();
        rsaKeyProperties.setAccessTokenExpiry(900_000L);
        rsaKeyProperties.setRefreshTokenExpiry(604_800_000L);
        seeder = new StaticClientSeeder(props, rsaKeyProperties, repo, jdbcTemplate);
    }

    private static RegisteredClient stubClient(String clientId) {
        // Minimal valid RegisteredClient for return values from findByClientId mocks.
        // Uses client_credentials grant to avoid auth_code's redirectUris validation.
        return RegisteredClient.withId("stub-" + clientId).clientId(clientId)
                .clientSecret("{noop}stub")
                .clientAuthenticationMethod(
                        org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(
                        org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private OidcClientProperties.ClientDefinition def(String id, String secret) {
        OidcClientProperties.ClientDefinition d = new OidcClientProperties.ClientDefinition();
        d.setClientId(id);
        d.setClientSecret(secret);
        d.setRedirectUris(new ArrayList<>(List.of("https://" + id + ".test/callback")));
        d.setPostLogoutRedirectUris(new ArrayList<>(List.of("https://" + id + ".test")));
        d.setScopes(new ArrayList<>(List.of("openid", "profile", "email")));
        return d;
    }

    @Test
    void seedsEmptyDb() {
        props.getClients().add(def("grafana", "{noop}gs"));
        props.getClients().add(def("ha", "{noop}hs"));
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(2);

        seeder.run(null);

        verify(repo, times(2)).save(any());
        // No explicit UPDATE for client_kind — relies on the DEFAULT 'sso' column value.
        verify(jdbcTemplate, never()).update(any(String.class), eq("sso"), any());
    }

    @Test
    void skipsExistingClient() {
        props.getClients().add(def("grafana", "{noop}gs"));
        when(repo.findByClientId("grafana")).thenReturn(stubClient("grafana"));
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(null);

        verify(repo, never()).save(any());
    }

    @Test
    void mixedExistingAndNew() {
        props.getClients().add(def("grafana", "{noop}gs"));
        props.getClients().add(def("ha", "{noop}hs"));
        props.getClients().add(def("n8n", "{noop}ns"));
        when(repo.findByClientId("grafana")).thenReturn(stubClient("grafana"));
        when(repo.findByClientId("ha")).thenReturn(null);
        when(repo.findByClientId("n8n")).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(3);

        seeder.run(null);

        verify(repo, times(2)).save(any());
    }

    @Test
    void persistedSecretEqualsYamlVerbatim() {
        // Critical: the seeder must NOT re-encode the YAML secret (F1 — double-hash bug).
        props.getClients().add(def("grafana", "{bcrypt}$2a$10$alreadyHashedValue"));
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(null);

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        assertThat(captor.getValue().getClientSecret())
                .isEqualTo("{bcrypt}$2a$10$alreadyHashedValue");
    }

    @Test
    void appliesYamlGrantTypes() {
        OidcClientProperties.ClientDefinition d = def("device-service", "{noop}s");
        d.setGrantTypes(new ArrayList<>(List.of("authorization_code", "refresh_token", "client_credentials")));
        props.getClients().add(d);
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(null);

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        assertThat(captor.getValue().getAuthorizationGrantTypes())
                .extracting(org.springframework.security.oauth2.core.AuthorizationGrantType::getValue)
                .containsExactlyInAnyOrder("authorization_code", "refresh_token", "client_credentials");
    }
}
