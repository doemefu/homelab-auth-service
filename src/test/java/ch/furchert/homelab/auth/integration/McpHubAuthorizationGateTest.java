package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gate G4b of docs/080 §4.5 (#107): consent page for claude-mcp-hub and the fail-closed, exact,
 * case-sensitive owner-only check on authorization requests (never on refresh).
 */
@ExtendWith(OutputCaptureExtension.class)
class McpHubAuthorizationGateTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    JWKSource<SecurityContext> jwkSource;
    @Autowired
    OidcClientProperties props;

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("hubowner", "password123", Role.USER);
        flow.createUser("hubadmin", "password123", Role.ADMIN);
        flow.createUser("HubOwner", "password456", Role.USER);
        flow.createUser("stranger", "password123", Role.USER);
        flow.forgetConsent(HUB, "hubowner");
    }

    @AfterEach
    void restoreAllowlist() {
        hub().setAllowedUsers(new ArrayList<>(List.of("hubowner", "hubadmin")));
    }

    private OidcClientProperties.ClientDefinition hub() {
        return props.findClient(HUB).orElseThrow();
    }

    private static AuthCodeFlow.Req hubReq() {
        return new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, HUB_RESOURCE);
    }

    @Test
    void allowlistedUserSeesConsentWithBothScopesAndGetsCodeOnlyAfterApproval() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        MvcResult consent = flow.authorizeAs(hubReq(), "hubowner", "password123", p);
        assertThat(consent.getResponse().getStatus()).isEqualTo(200);
        String html = consent.getResponse().getContentAsString();
        assertThat(html).contains("claude-mcp-hub").contains("mail:read").contains("calendar:read");
        assertThat(consent.getResponse().getRedirectedUrl()).isNull();          // no code yet
        String location = flow.approveConsent(consent, HUB, "mail:read", "calendar:read").getResponse().getRedirectedUrl();
        assertThat(location).startsWith(HUB_CALLBACK);
        assertThat(AuthCodeFlow.param(location, "code")).isNotBlank();
    }

    @Test
    void userNotOnAllowlistIsRejectedWithoutConsentPage(CapturedOutput out) throws Exception {
        MvcResult r = flow.authorizeAs(hubReq(), "stranger", "password123", AuthCodeFlow.pkce());
        assertRejected(r);
        assertThat(out.getOut()).contains("rejected: user is not on its allowlist")
                .doesNotContain("stranger").doesNotContain("password123");
    }

    @Test
    void userDifferingOnlyInLetterCaseIsRejected() throws Exception {
        assertRejected(flow.authorizeAs(hubReq(), "HubOwner", "password456", AuthCodeFlow.pkce()));
    }

    @Test
    void loginLookupIsCaseSensitive() throws Exception {
        // Pins the premise of the exact rule: typing another case does not authenticate as the stored user.
        MvcResult first = flow.authorizeAnonymous(hubReq(), AuthCodeFlow.pkce());
        mockMvc.perform(post("/login").param("username", "HUBOWNER").param("password", "password123")
                        .session((MockHttpSession) first.getRequest().getSession()).with(csrf()))
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void emptyAllowlistRejectsEveryoneButOtherClientsStillWork() throws Exception {
        hub().setAllowedUsers(new ArrayList<>());
        assertRejected(flow.authorizeAs(hubReq(), "hubowner", "password123", AuthCodeFlow.pkce()));
        // another client's login with the same user still issues a code
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req("furchert-ch",
                        "https://furchert.test.local/api/auth/callback/furchert-ch", "openid profile email", null),
                "hubowner", "password123", p);
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code")).isNotBlank();
    }

    @Test
    void refreshStillWorksAfterRemovalFromAllowlist() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        hub().setAllowedUsers(new ArrayList<>(List.of("hubadmin")));
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE).andExpect(status().isOk());
    }

    @Test
    void unauthenticatedHubRequestStillRedirectsToLogin() throws Exception {
        MvcResult r = flow.authorizeAnonymous(hubReq(), AuthCodeFlow.pkce());
        assertThat(r.getResponse().getRedirectedUrl()).contains("/login");
    }

    private void assertRejected(MvcResult r) throws Exception {
        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(HUB_CALLBACK);
        assertThat(AuthCodeFlow.param(location, "error")).isEqualTo("access_denied");
        assertThat(AuthCodeFlow.param(location, "code")).isNull();
        assertThat(r.getResponse().getContentAsString()).doesNotContain("calendar:read"); // no consent page
    }
}
