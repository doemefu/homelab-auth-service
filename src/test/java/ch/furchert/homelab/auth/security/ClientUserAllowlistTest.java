package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class ClientUserAllowlistTest {

    private static final RegisteredClient HUB = client("claude-mcp-hub", true);
    private static final RegisteredClient GRAFANA = client("grafana", false);

    @Test
    void exactCaseSensitiveMatch() {
        ClientUserAllowlist a = allowlist(true, "hubowner");
        assertThat(a.permits(HUB, "hubowner")).isTrue();
        assertThat(a.permits(HUB, "HubOwner")).isFalse();
        assertThat(a.permits(HUB, "hubowner2")).isFalse();
    }

    @Test
    void blankEntriesAreIgnored() {
        ClientUserAllowlist a = allowlist(true, " ", "", " hubowner ");
        assertThat(a.permits(HUB, "")).isFalse();
        assertThat(a.permits(HUB, " ")).isFalse();
        assertThat(a.permits(HUB, "hubowner")).isTrue();
    }

    @Test
    void emptyListIsFailClosed() {
        assertThat(allowlist(true).permits(HUB, "hubowner")).isFalse();
    }

    @Test
    void nullUsernameIsRejected() {
        assertThat(allowlist(true, "hubowner").permits(HUB, null)).isFalse();
    }

    @Test
    void unrestrictedAndUnknownClientsAreNotAffected() {
        ClientUserAllowlist a = allowlist(false);
        assertThat(a.permits(HUB, "anyone")).isTrue();
        assertThat(a.permits(GRAFANA, "anyone")).isTrue();
    }

    @Test
    void markedClientWithoutDefinitionIsRejected() {
        // No definition for a row seeded as audience-bound → nobody, not "unrestricted".
        ClientUserAllowlist a = new ClientUserAllowlist(new OidcClientProperties());
        assertThat(a.permits(HUB, "hubowner")).isFalse();
        assertThat(a.permits(GRAFANA, "anyone")).isTrue();   // unmarked unknown client: unchanged
    }

    @Test
    void startupWarnsOncePerClientWithEmptyAllowlist(CapturedOutput out) {
        allowlist(true, " ").warnIfUnconfigured();
        assertThat(out.getOut()).containsOnlyOnce("claude-mcp-hub").contains("WARN");
    }

    @Test
    void startupIsQuietWhenConfigured(CapturedOutput out) {
        allowlist(true, "hubowner").warnIfUnconfigured();
        assertThat(out.getOut()).doesNotContain("claude-mcp-hub");
    }

    private static ClientUserAllowlist allowlist(boolean restrict, String... users) {
        OidcClientProperties props = new OidcClientProperties();
        OidcClientProperties.ClientDefinition hub = new OidcClientProperties.ClientDefinition();
        hub.setClientId("claude-mcp-hub");
        hub.setAccessTokenAudience("https://mcp.furchert.ch/mcp");
        hub.setRestrictToAllowedUsers(restrict);
        hub.setAllowedUsers(new ArrayList<>(List.of(users)));
        props.getClients().add(hub);
        return new ClientUserAllowlist(props);
    }

    private static RegisteredClient client(String clientId, boolean marked) {
        ClientSettings.Builder settings = ClientSettings.builder();
        if (marked) {
            settings.setting(OidcClientProperties.AUDIENCE_BOUND_SETTING, true);
        }
        return RegisteredClient.withId(clientId + "-id").clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.test.local/cb").clientSettings(settings.build()).build();
    }
}
