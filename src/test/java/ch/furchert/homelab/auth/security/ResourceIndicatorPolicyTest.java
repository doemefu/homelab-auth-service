package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import org.junit.jupiter.api.BeforeEach;
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
class ResourceIndicatorPolicyTest {

    private static final RegisteredClient HUB_CLIENT = client("claude-mcp-hub", true);
    private OidcClientProperties props;
    private ResourceIndicatorPolicy policy;

    @BeforeEach
    void setUp() {
        props = new OidcClientProperties();
        OidcClientProperties.ClientDefinition hub = new OidcClientProperties.ClientDefinition();
        hub.setClientId("claude-mcp-hub");
        hub.setAccessTokenAudience("https://mcp.furchert.ch/mcp");
        hub.setAllowedResources(new ArrayList<>(List.of("https://mcp.furchert.ch/mcp")));
        OidcClientProperties.ClientDefinition other = new OidcClientProperties.ClientDefinition();
        other.setClientId("grafana");
        props.getClients().addAll(List.of(hub, other));
        policy = new ResourceIndicatorPolicy(props);
    }

    @Test
    void absentResourceIsAllowed() {
        assertThat(policy.isAllowed(HUB_CLIENT, List.of())).isTrue();
    }

    @Test
    void exactValueIsAllowed() {
        assertThat(policy.isAllowed(HUB_CLIENT, List.of("https://mcp.furchert.ch/mcp"))).isTrue();
    }

    @Test
    void variantsAreRejectedAndLogged(CapturedOutput out) {
        assertThat(policy.isAllowed(HUB_CLIENT, List.of("https://mcp.furchert.ch/mcp/"))).isFalse();
        assertThat(policy.isAllowed(HUB_CLIENT, List.of("https://mcp.furchert.ch"))).isFalse();
        assertThat(policy.isAllowed(HUB_CLIENT, List.of(""))).isFalse();
        assertThat(out.getOut()).contains("https://mcp.furchert.ch/mcp/").contains("invalid_target");
    }

    @Test
    void anyDisallowedValueAmongSeveralRejects() {
        assertThat(policy.isAllowed(HUB_CLIENT,
                List.of("https://mcp.furchert.ch/mcp", "https://other.example/api"))).isFalse();
    }

    @Test
    void clientsWithoutAllowedListIgnoreTheParameter() {
        assertThat(policy.isAllowed(client("grafana", false), List.of("https://anything.example"))).isTrue();
        assertThat(policy.isAllowed(client("unknown-device-client", false), List.of("x"))).isTrue();
    }

    @Test
    void markedClientWithoutDefinitionIsRejected() {
        // A row seeded as audience-bound whose configuration entry was removed or renamed fails closed,
        // even without a resource parameter.
        props.getClients().removeIf(c -> "claude-mcp-hub".equals(c.getClientId()));
        assertThat(policy.isAllowed(HUB_CLIENT, List.of())).isFalse();
        assertThat(policy.isAllowed(HUB_CLIENT, List.of("https://mcp.furchert.ch/mcp"))).isFalse();
    }

    @Test
    void valuesAcceptsStringArrayAndNull() {
        assertThat(ResourceIndicatorPolicy.values(null)).isEmpty();
        assertThat(ResourceIndicatorPolicy.values("a")).containsExactly("a");
        assertThat(ResourceIndicatorPolicy.values(new String[]{"a", "b"})).containsExactly("a", "b");
    }

    @Test
    void sanitiseReplacesControlCharactersAndTruncates() {
        assertThat(ResourceIndicatorPolicy.sanitise("a\r\nFAKE LOG")).isEqualTo("a??FAKE LOG");
        // Unicode line breaks outside ASCII \p{Cntrl}: NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR.
        assertThat(ResourceIndicatorPolicy.sanitise("a\u0085b c d")).isEqualTo("a?b?c?d");
        assertThat(ResourceIndicatorPolicy.sanitise("x".repeat(500))).hasSize(203).endsWith("...");
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
