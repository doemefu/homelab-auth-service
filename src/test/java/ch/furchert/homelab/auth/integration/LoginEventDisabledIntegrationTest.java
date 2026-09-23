package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.service.LoginEventFeature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * NM-4 overnight hard rule: with neither {@code LOGIN_EVENT_HMAC_KEY} nor
 * {@code DATA_SERVICE_CLIENT_SECRET} configured (the state right after a Flux auto-deploy, before
 * playbook 59 created the Secret keys) the application context starts, logins keep working,
 * nothing is recorded and the endpoint answers 503. Uses the shared default test context, which
 * configures neither.
 */
class LoginEventDisabledIntegrationTest extends AbstractIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired LoginEventFeature feature;
    @Autowired JdbcTemplate jdbcTemplate;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @Test
    void contextStartsWithFeatureDisabled() {
        assertThat(feature.isEnabled()).isFalse();
    }

    @Test
    void loginStillWorksAndNothingIsRecorded() throws Exception {
        if (userRepository.findByUsername("le-disabled-user").isEmpty()) {
            User user = new User();
            user.setUsername("le-disabled-user");
            user.setEmail("le-disabled-user@test.local");
            user.setPasswordHash(passwordEncoder.encode("password123"));
            user.setRole(Role.USER);
            userRepository.save(user);
        }
        Long before = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM login_event_outbox", Long.class);

        mockMvc.perform(post("/login").param("username", "le-disabled-user").param("password", "password123")
                        .header("CF-Connecting-IP", "203.0.113.9")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("error"));
        mockMvc.perform(post("/login").param("username", "le-disabled-user").param("password", "wrong")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        Thread.sleep(300);
        Integer after = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM login_event_outbox WHERE id > ?", Integer.class, before);
        assertThat(after).isZero();
    }

    @Test
    void endpointAnswers503ForScopedTokenAnd403WithoutScope() throws Exception {
        var scoped = SecurityMockMvcRequestPostProcessors.jwt()
                .authorities(new SimpleGrantedAuthority("SCOPE_login-events:read"))
                .jwt(j -> j.subject("data-service"));
        mockMvc.perform(get("/api/v1/login-events").with(scoped))
                .andExpect(status().isServiceUnavailable());

        var admin = SecurityMockMvcRequestPostProcessors.jwt()
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
        mockMvc.perform(get("/api/v1/login-events").with(admin))
                .andExpect(status().isForbidden());
    }
}
