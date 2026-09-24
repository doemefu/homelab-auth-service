package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.dto.LoginEventResponse;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.LoginEventOutboxRepository;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.security.UsernameHmac;
import ch.furchert.homelab.auth.service.LoginEventFeature;
import ch.furchert.homelab.auth.service.LoginEventPurgeJob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * NM-4 (#94, docs/060 §7.6): login-event capture, outbox, pull endpoint and purge with the
 * feature ENABLED (HMAC key + data-service client secret configured). The default
 * {@link AbstractIntegrationTest} context has neither and is covered by
 * {@link LoginEventDisabledIntegrationTest}.
 */
class LoginEventOutboxIntegrationTest extends AbstractIntegrationTest {

    static final String HMAC_KEY = "test-login-event-hmac-key-0123456789abcdef";

    @DynamicPropertySource
    static void loginEventProperties(DynamicPropertyRegistry registry) {
        registry.add("app.oidc.clients[6].client-id", () -> "data-service");
        registry.add("app.oidc.clients[6].client-secret", () -> "{noop}data-service-secret");
        registry.add("app.oidc.clients[6].scopes[0]", () -> "login-events:read");
        registry.add("app.oidc.clients[6].grant-types[0]", () -> "client_credentials");
        registry.add("app.login-events.hmac-key", () -> HMAC_KEY);
        // No settle delay in tests; the settle filter itself is covered in settleWindowHidesFreshRows.
        registry.add("app.login-events.settle", () -> "0s");
    }

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired ObjectMapper objectMapper;
    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired UsernameHmac usernameHmac;
    @Autowired LoginEventFeature feature;
    @Autowired LoginEventOutboxRepository outboxRepository;
    @Autowired LoginEventPurgeJob purgeJob;

    @BeforeEach
    void users() {
        ensureUser("le-active", "ACTIVE");
        ensureUser("le-inactive", "INACTIVE");
    }

    private void ensureUser(String username, String status) {
        if (userRepository.findByUsername(username).isEmpty()) {
            User user = new User();
            user.setUsername(username);
            user.setEmail(username + "@test.local");
            user.setPasswordHash(passwordEncoder.encode("password123"));
            user.setRole(Role.USER);
            user.setStatus(status);
            userRepository.save(user);
        }
    }

    // --- capture -------------------------------------------------------------------------

    @Test
    void featureIsEnabledAndDataServiceClientIsSeeded(@Autowired RegisteredClientRepository clients) {
        assertThat(feature.isEnabled()).isTrue();
        var ds = clients.findByClientId("data-service");
        assertThat(ds).isNotNull();
        assertThat(ds.getRedirectUris()).isEmpty();
        assertThat(ds.getScopes()).containsExactly("login-events:read");
    }

    @Test
    void successfulLoginRecordsSuccessWithSubjectAndCfIp() throws Exception {
        long before = maxId();
        mockMvc.perform(post("/login").param("username", "le-active").param("password", "password123")
                        .header("CF-Connecting-IP", "203.0.113.7")
                        .header("User-Agent", "IT-Agent/1.0")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("error"));

        Map<String, Object> row = awaitSingleRow(before, usernameHmac.hash("le-active"));
        assertThat(row.get("outcome")).isEqualTo("success");
        assertThat(row.get("subject")).isEqualTo("le-active");
        assertThat(row.get("client_ip")).isEqualTo("203.0.113.7");
        assertThat(row.get("ip_source")).isEqualTo("cf-connecting-ip");
        assertThat(row.get("user_agent")).isEqualTo("IT-Agent/1.0");
    }

    @Test
    void wrongPasswordRecordsFailureWithoutPlaintextUsername() throws Exception {
        long before = maxId();
        mockMvc.perform(post("/login").param("username", " LE-Active ").param("password", "wrong")
                        .header("CF-Connecting-IP", "2001:db8::7")
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?error"));

        // Normalised HMAC: the failure for " LE-Active " links to the success hash of "le-active".
        Map<String, Object> row = awaitSingleRow(before, usernameHmac.hash("le-active"));
        assertThat(row.get("outcome")).isEqualTo("failure");
        assertThat(row.get("subject")).isNull();
        assertThat(row.get("client_ip")).isEqualTo("2001:db8::7");
        assertThat(row.get("ip_source")).isEqualTo("cf-connecting-ip");
        assertThat(row.get("user_agent")).isNull();
        assertNoPlaintextUsernameStored(before, "le-active");
    }

    @Test
    void unknownUserRecordsFailureAndFallsBackToRemoteAddr() throws Exception {
        long before = maxId();
        mockMvc.perform(post("/login").param("username", "hunter2-typed-as-username").param("password", "x")
                        .with(request -> {
                            request.setRemoteAddr("198.51.100.9");
                            return request;
                        })
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?error"));

        Map<String, Object> row = awaitSingleRow(before, usernameHmac.hash("hunter2-typed-as-username"));
        assertThat(row.get("outcome")).isEqualTo("failure");
        assertThat(row.get("client_ip")).isEqualTo("198.51.100.9");
        assertThat(row.get("ip_source")).isEqualTo("remote-addr");
        assertNoPlaintextUsernameStored(before, "hunter2-typed-as-username");
    }

    @Test
    void inactiveUserRecordsLockedEvenWithCorrectPassword() throws Exception {
        long before = maxId();
        mockMvc.perform(post("/login").param("username", "le-inactive").param("password", "password123")
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?error"));

        Map<String, Object> row = awaitSingleRow(before, usernameHmac.hash("le-inactive"));
        assertThat(row.get("outcome")).isEqualTo("locked");
        assertThat(row.get("subject")).isNull();
    }

    @Test
    void bearerTokenAuthenticationsAreNotRecorded() throws Exception {
        long before = maxId();
        String token = dataServiceToken();
        mockMvc.perform(get("/api/v1/login-events").param("after", String.valueOf(before))
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        Thread.sleep(300);
        assertThat(countAfter(before)).isZero();
    }

    // --- endpoint --------------------------------------------------------------------------

    @Test
    void dataServiceTokenReadsEventsWithContractShape() throws Exception {
        long before = maxId();
        mockMvc.perform(post("/login").param("username", "le-shape").param("password", "x")
                        .header("CF-Connecting-IP", "203.0.113.8")
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?error"));
        awaitSingleRow(before, usernameHmac.hash("le-shape"));

        MvcResult result = mockMvc.perform(get("/api/v1/login-events").param("after", String.valueOf(before))
                        .header("Authorization", "Bearer " + dataServiceToken()))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("hasMore").asBoolean()).isFalse();
        JsonNode events = body.get("events");
        assertThat(events.size()).isEqualTo(1);
        JsonNode e = events.get(0);
        assertThat(body.get("nextAfter").asLong()).isEqualTo(e.get("id").asLong());
        assertThat(UUID.fromString(e.get("eventId").asString())).isNotNull();
        assertThat(e.get("occurredAt").asString()).endsWith("Z");
        assertThat(e.get("outcome").asString()).isEqualTo("failure");
        assertThat(e.get("clientIp").asString()).isEqualTo("203.0.113.8");
        assertThat(e.get("ipSource").asString()).isEqualTo("cf-connecting-ip");
        assertThat(e.get("usernameHmac").asString()).matches("[0-9a-f]{64}");
        // Absent values are serialised as null, never omitted (docs/060 §7.1).
        assertThat(e.has("subject")).isTrue();
        assertThat(e.get("subject").isNull()).isTrue();
        assertThat(e.has("userAgent")).isTrue();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("le-shape");
    }

    @Test
    void cursorPagingWalksAllRows() throws Exception {
        long before = maxId();
        for (int i = 0; i < 3; i++) {
            insertRow(UUID.randomUUID(), "now() - interval '1 minute'");
        }
        String token = dataServiceToken();

        JsonNode first = page(token, before, 2);
        assertThat(first.get("events").size()).isEqualTo(2);
        assertThat(first.get("hasMore").asBoolean()).isTrue();
        long next = first.get("nextAfter").asLong();
        assertThat(next).isEqualTo(first.get("events").get(1).get("id").asLong());

        JsonNode second = page(token, next, 2);
        assertThat(second.get("events").size()).isEqualTo(1);
        assertThat(second.get("hasMore").asBoolean()).isFalse();

        JsonNode empty = page(token, second.get("nextAfter").asLong(), 2);
        assertThat(empty.get("events").size()).isZero();
        assertThat(empty.get("nextAfter").asLong()).isEqualTo(second.get("nextAfter").asLong());
    }

    @Test
    void settleWindowHidesFreshRows() {
        long before = maxId();
        insertRow(UUID.randomUUID(), "now()");
        assertThat(outboxRepository.findAfter(before, 10, Duration.ofSeconds(10))).isEmpty();
        List<LoginEventResponse> settled = outboxRepository.findAfter(before, 10, Duration.ZERO);
        assertThat(settled).hasSize(1);
    }

    @Test
    void adminUserTokenIsForbidden() throws Exception {
        var admin = SecurityMockMvcRequestPostProcessors.jwt()
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                .jwt(j -> j.subject("admin").claim("role", "ADMIN"));
        mockMvc.perform(get("/api/v1/login-events").with(admin))
                .andExpect(status().isForbidden());
    }

    @Test
    void clientWithoutScopeIsForbidden() throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                "device-service:device-service-secret".getBytes(StandardCharsets.UTF_8));
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&scope=clients:admin"))
                .andExpect(status().isOk())
                .andReturn();
        String token = objectMapper.readTree(tokenResult.getResponse().getContentAsString())
                .get("access_token").asString();

        mockMvc.perform(get("/api/v1/login-events").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void otherClientCannotRequestTheScope() throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                "device-service:device-service-secret".getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&scope=login-events:read"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void noTokenIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/login-events")).andExpect(status().isUnauthorized());
    }

    @Test
    void invalidParametersAreBadRequest() throws Exception {
        String token = dataServiceToken();
        for (String[] p : List.of(new String[]{"limit", "0"}, new String[]{"limit", "1001"},
                new String[]{"after", "-1"}, new String[]{"after", "abc"})) {
            mockMvc.perform(get("/api/v1/login-events").param(p[0], p[1])
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isBadRequest());
        }
        mockMvc.perform(get("/api/v1/login-events").param("limit", "1000")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    // --- purge -----------------------------------------------------------------------------

    @Test
    void purgeRemovesRowsOlderThan72Hours() {
        UUID old = UUID.randomUUID();
        UUID young = UUID.randomUUID();
        insertRow(old, "now() - interval '73 hours'");
        insertRow(young, "now() - interval '71 hours'");

        purgeJob.purge();

        assertThat(exists(old)).isFalse();
        assertThat(exists(young)).isTrue();
    }

    // --- helpers ---------------------------------------------------------------------------

    private String dataServiceToken() throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                "data-service:data-service-secret".getBytes(StandardCharsets.UTF_8));
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&scope=login-events:read"))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("access_token").asString();
    }

    private JsonNode page(String token, long after, int limit) throws Exception {
        MvcResult r = mockMvc.perform(get("/api/v1/login-events")
                        .param("after", String.valueOf(after)).param("limit", String.valueOf(limit))
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString());
    }

    private long maxId() {
        Long max = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM login_event_outbox", Long.class);
        return max == null ? 0 : max;
    }

    private int countAfter(long id) {
        Integer n = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM login_event_outbox WHERE id > ?",
                Integer.class, id);
        return n == null ? 0 : n;
    }

    private Map<String, Object> awaitSingleRow(long afterId, String hmac) throws InterruptedException {
        String sql = """
                SELECT outcome, host(client_ip) AS client_ip, ip_source, subject, user_agent
                FROM login_event_outbox WHERE id > ? AND username_hmac = ?
                """;
        for (int i = 0; i < 50; i++) {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, afterId, hmac);
            if (!rows.isEmpty()) {
                Thread.sleep(200); // a duplicate event would land in the same window
                rows = jdbcTemplate.queryForList(sql, afterId, hmac);
                assertThat(rows).as("exactly one event per login attempt").hasSize(1);
                return rows.getFirst();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("no login event recorded within 5 s");
    }

    private void assertNoPlaintextUsernameStored(long afterId, String username) {
        Integer n = jdbcTemplate.queryForObject("""
                SELECT COUNT(*) FROM login_event_outbox
                WHERE id > ? AND (subject ILIKE ? OR user_agent ILIKE ?)
                """, Integer.class, afterId, "%" + username + "%", "%" + username + "%");
        assertThat(n).isZero();
    }

    private void insertRow(UUID eventId, String recordedAtSql) {
        jdbcTemplate.update("INSERT INTO login_event_outbox "
                + "(event_id, occurred_at, outcome, client_ip, ip_source, username_hmac, recorded_at) "
                + "VALUES (?, now(), 'failure', '192.0.2.1', 'remote-addr', ?, " + recordedAtSql + ")",
                eventId, "b".repeat(64));
    }

    private boolean exists(UUID eventId) {
        Integer n = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM login_event_outbox WHERE event_id = ?",
                Integer.class, eventId);
        return n != null && n > 0;
    }
}
