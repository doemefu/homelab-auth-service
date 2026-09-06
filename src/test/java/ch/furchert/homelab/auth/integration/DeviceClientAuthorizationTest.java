package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full application-context guard for the {@code /api/v1/clients} admin API (#46):
 * a caller with only {@code ROLE_USER} (no ADMIN role, no {@code clients:admin} scope)
 * must receive 403 from every endpoint. {@link DeviceClientControllerTest} already
 * asserts the same rule as a {@code @WebMvcTest} slice; this test proves it holds in
 * the full Spring context (real {@code @EnableMethodSecurity} + both filter chains),
 * so an accidental removal of the method-security guard would be caught here even if
 * the slice test were also broken or removed.
 * <p>
 * Named {@code ...Test.java} (not {@code ...IT.java}) so Maven Surefire's default
 * include glob (<code>**&#47;*Test.java</code>) actually picks it up — this project has
 * no {@code maven-failsafe-plugin} bound, so an {@code IT}-suffixed class would never
 * run under {@code ./mvnw test}/{@code verify} (see #85).
 */
class DeviceClientAuthorizationTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void nonAdminUser_isForbiddenOnAllClientEndpoints() throws Exception {
        var nonAdminUser = SecurityMockMvcRequestPostProcessors.jwt()
                .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                .jwt(j -> j.subject("plainuser"));

        mockMvc.perform(post("/api/v1/clients")
                        .with(nonAdminUser)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"terra-guard\",\"description\":null}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/clients")
                        .with(nonAdminUser))
                .andExpect(status().isForbidden());

        // terra-guard was never created (the POST above was rejected before it could
        // persist anything), so this also proves the guard runs before the service
        // layer would otherwise have to distinguish "forbidden" from "not found".
        mockMvc.perform(delete("/api/v1/clients/terra-guard")
                        .with(nonAdminUser))
                .andExpect(status().isForbidden());
    }
}
