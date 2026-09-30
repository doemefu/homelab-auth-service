package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class, OutputCaptureExtension.class})
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

    private void stubKind(String clientId, String kind) {
        when(jdbcTemplate.queryForObject("SELECT client_kind FROM oauth2_registered_client WHERE client_id = ?",
                String.class, clientId)).thenReturn(kind);
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

        seeder.run(mock(ApplicationArguments.class));

        verify(repo, times(2)).save(any());
        // No explicit UPDATE for client_kind — relies on the DEFAULT 'sso' column value.
        verify(jdbcTemplate, never()).update(any(String.class), eq("sso"), any());
    }

    @Test
    void skipsExistingClient() {
        props.getClients().add(def("grafana", "{noop}gs"));
        when(repo.findByClientId("grafana")).thenReturn(stubClient("grafana"));
        stubKind("grafana", "sso");
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        verify(repo, never()).save(any());
    }

    @Test
    void mixedExistingAndNew() {
        props.getClients().add(def("grafana", "{noop}gs"));
        props.getClients().add(def("ha", "{noop}hs"));
        props.getClients().add(def("n8n", "{noop}ns"));
        when(repo.findByClientId("grafana")).thenReturn(stubClient("grafana"));
        stubKind("grafana", "sso");
        when(repo.findByClientId("ha")).thenReturn(null);
        when(repo.findByClientId("n8n")).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(3);

        seeder.run(mock(ApplicationArguments.class));

        verify(repo, times(2)).save(any());
    }

    @Test
    void persistedSecretEqualsYamlVerbatim() {
        // Critical: the seeder must NOT re-encode the YAML secret (F1 — double-hash bug).
        props.getClients().add(def("grafana", "{bcrypt}$2a$10$alreadyHashedValue"));
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

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

        seeder.run(mock(ApplicationArguments.class));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        assertThat(captor.getValue().getAuthorizationGrantTypes())
                .extracting(org.springframework.security.oauth2.core.AuthorizationGrantType::getValue)
                .containsExactlyInAnyOrder("authorization_code", "refresh_token", "client_credentials");
    }

    @Test
    void skipsClientWithBlankSecret() {
        // NM-4: data-service's secret env var defaults to empty so a missing Secret key cannot
        // stop the IdP; such a client must not be seeded (and must not even be looked up).
        props.getClients().add(def("grafana", "{noop}gs"));
        props.getClients().add(def("data-service", ""));
        props.getClients().add(def("other", null));
        when(repo.findByClientId("grafana")).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo, times(1)).save(captor.capture());
        assertThat(captor.getValue().getClientId()).isEqualTo("grafana");
        verify(repo, never()).findByClientId("data-service");
        verify(repo, never()).findByClientId("other");
    }

    @Test
    void seedsClientCredentialsOnlyClientWithoutRedirectUris() {
        // docs/060 §12 unverified item: a client_credentials-only client with no redirect URIs builds.
        OidcClientProperties.ClientDefinition d = new OidcClientProperties.ClientDefinition();
        d.setClientId("data-service");
        d.setClientSecret("{noop}ds");
        d.setScopes(new ArrayList<>(List.of("login-events:read")));
        d.setGrantTypes(new ArrayList<>(List.of("client_credentials")));
        props.getClients().add(d);
        when(repo.findByClientId("data-service")).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        RegisteredClient saved = captor.getValue();
        assertThat(saved.getRedirectUris()).isEmpty();
        assertThat(saved.getScopes()).containsExactly("login-events:read");
        assertThat(saved.getAuthorizationGrantTypes()).extracting(g -> g.getValue())
                .containsExactly("client_credentials");
    }

    @Test
    void warnsWhenAnotherKindOfClientHoldsTheClientId(CapturedOutput out) {
        props.getClients().add(def("claude-mcp-hub", "{noop}s"));
        when(repo.findByClientId("claude-mcp-hub")).thenReturn(stubClient("claude-mcp-hub"));
        stubKind("claude-mcp-hub", "device");
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        verify(repo, never()).save(any());
        assertThat(out.getOut()).contains("WARN").contains("'claude-mcp-hub'").doesNotContain("device");
    }

    @Test
    void existingSsoRowIsSkippedWithoutWarning(CapturedOutput out) {
        props.getClients().add(def("grafana", "{noop}gs"));
        when(repo.findByClientId("grafana")).thenReturn(stubClient("grafana"));
        stubKind("grafana", "sso");
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        verify(repo, never()).save(any());
        assertThat(out.getOut()).doesNotContain("WARN");
    }

    @Test
    void defaultsKeepTodaysSettings() {
        props.getClients().add(def("grafana", "{noop}gs"));
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        RegisteredClient saved = captor.getValue();
        assertThat(saved.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(saved.getClientSettings().isRequireAuthorizationConsent()).isFalse();
        assertThat(saved.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(saved.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
        assertThat(saved.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
        assertThat(saved.getTokenSettings().isReuseRefreshTokens()).isTrue();
        assertThat(saved.getClientSettings().getSettings())
                .doesNotContainKey(OidcClientProperties.AUDIENCE_BOUND_SETTING);   // existing clients: no marker
    }

    @Test
    void appliesPerClientSettings() {
        OidcClientProperties.ClientDefinition d = def("claude-mcp-hub", "{noop}s");
        d.setScopes(new ArrayList<>(List.of("mail:read", "calendar:read")));
        d.setClientAuthenticationMethods(new ArrayList<>(List.of("client_secret_basic", "client_secret_post")));
        d.setReuseRefreshTokens(false);
        d.setRequireAuthorizationConsent(true);
        d.setAccessTokenTimeToLive(Duration.ofMinutes(10));
        d.setAccessTokenAudience("https://mcp.furchert.ch/mcp");
        props.getClients().add(d);
        when(repo.findByClientId(any())).thenReturn(null);
        when(jdbcTemplate.queryForObject(any(String.class), eq(Integer.class))).thenReturn(1);

        seeder.run(mock(ApplicationArguments.class));

        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repo).save(captor.capture());
        RegisteredClient saved = captor.getValue();
        assertThat(saved.getClientAuthenticationMethods()).containsExactlyInAnyOrder(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
        assertThat(saved.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(saved.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
        assertThat(saved.getTokenSettings().isReuseRefreshTokens()).isFalse();
        assertThat(saved.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
        // Fail-closed marker for audience-bound clients: a plain Boolean in client_settings.
        assertThat(saved.getClientSettings().<Object>getSetting(OidcClientProperties.AUDIENCE_BOUND_SETTING))
                .isEqualTo(Boolean.TRUE);
    }

    @Test
    void findClientMatchesExactClientId() {
        props.getClients().add(def("grafana", "{noop}gs"));
        assertThat(props.findClient("grafana")).isPresent();
        assertThat(props.findClient("Grafana")).isEmpty();
        assertThat(props.findClient(null)).isEmpty();
    }

    @Test
    void markedClientWithoutDefinitionOrAudienceIsDetected() {
        OidcClientProperties.ClientDefinition hub = def("claude-mcp-hub", "{noop}s");
        hub.setAccessTokenAudience("https://mcp.furchert.ch/mcp");
        props.getClients().add(hub);
        RegisteredClient marked = client("claude-mcp-hub", true);
        assertThat(props.isAudienceBoundWithoutDefinition(marked)).isFalse();      // definition present
        hub.setAccessTokenAudience(" ");
        assertThat(props.isAudienceBoundWithoutDefinition(marked)).isTrue();       // audience removed
        props.getClients().clear();
        assertThat(props.isAudienceBoundWithoutDefinition(marked)).isTrue();       // entry removed or renamed
        assertThat(props.isAudienceBoundWithoutDefinition(client("grafana", false))).isFalse();   // unmarked: never
    }

    private static RegisteredClient client(String clientId, boolean marked) {
        ClientSettings.Builder settings = ClientSettings.builder();
        if (marked) settings.setting(OidcClientProperties.AUDIENCE_BOUND_SETTING, true);
        return RegisteredClient.withId(clientId + "-id").clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.test.local/cb").clientSettings(settings.build()).build();
    }
}
