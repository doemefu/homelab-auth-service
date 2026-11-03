package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** #106 item 1: for a non-admin caller, another user's id looks exactly like an absent id. */
class UserIdEnumerationIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    ObjectMapper objectMapper;

    private long otherId;

    @BeforeEach
    void users() {
        user("enum-caller");
        otherId = user("enum-other").getId();
    }

    private User user(String name) {
        return userRepository.findByUsername(name).orElseGet(() -> {
            User u = new User();
            u.setUsername(name);
            u.setEmail(name + "@test.local");
            u.setPasswordHash(passwordEncoder.encode("irrelevant-" + name));
            u.setRole(Role.USER);
            u.setStatus("ACTIVE");
            return userRepository.save(u);
        });
    }

    private JsonNode call(MockHttpServletRequestBuilder request, int expectedStatus) throws Exception {
        MvcResult result = mockMvc.perform(request.with(jwt().jwt(j -> j.subject("enum-caller"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")))).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus);
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private static MockHttpServletRequestBuilder reset(long id) {
        return post("/api/v1/users/" + id + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"whatever-1\",\"newPassword\":\"new-password-123\"}");
    }

    /** Same keys and the same error text (apart from the id itself); the timestamp differs by nature. */
    private void assertSameShape(JsonNode other, JsonNode missing, long absent) {
        assertThat(objectMapper.convertValue(other, java.util.Map.class).keySet())
                .isEqualTo(objectMapper.convertValue(missing, java.util.Map.class).keySet());
        assertThat(other.get("error").asString()).isEqualTo(
                missing.get("error").asString().replace(String.valueOf(absent), String.valueOf(otherId)));
    }

    @Test
    void anotherUsersIdAnswersLikeAnAbsentIdOnGet() throws Exception {
        long absent = otherId + 1_000_000;
        JsonNode other = call(get("/api/v1/users/" + otherId), 404);
        JsonNode missing = call(get("/api/v1/users/" + absent), 404);
        assertSameShape(other, missing, absent);
    }

    @Test
    void anotherUsersIdAnswersLikeAnAbsentIdOnResetPassword() throws Exception {
        long absent = otherId + 1_000_000;
        JsonNode other = call(reset(otherId), 404);
        JsonNode missing = call(reset(absent), 404);
        assertSameShape(other, missing, absent);
    }
}
