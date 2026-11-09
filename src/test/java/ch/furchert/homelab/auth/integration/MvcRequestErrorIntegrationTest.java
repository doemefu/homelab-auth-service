package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * #147: Spring MVC request errors (no handler, unsupported method, unsupported or unacceptable media type)
 * keep their own status in the usual JSON error shape instead of 500. Security-chain answers for anonymous
 * callers and token-endpoint errors are unchanged.
 */
@ExtendWith(OutputCaptureExtension.class)
class MvcRequestErrorIntegrationTest extends AbstractIntegrationTest {

    private static final String UNKNOWN = "wa147-unknown";

    @Autowired
    MockMvc mockMvc;

    private static RequestPostProcessor admin() {
        return SecurityMockMvcRequestPostProcessors.jwt()
                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")).jwt(j -> j.subject("wa147-admin"));
    }

    private static RequestPostProcessor signedIn() {
        return SecurityMockMvcRequestPostProcessors.user("wa147-user").roles("USER");
    }

    private static String furchertChBasic() {
        return "Basic " + Base64.getEncoder().encodeToString("furchert-ch:furchert-ch-secret".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void unknownApiPathAnswers404WithoutEchoingThePath(CapturedOutput output) throws Exception {
        MvcResult r = mockMvc.perform(get("/api/v1/" + UNKNOWN).with(admin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andReturn();
        assertThat(r.getResponse().getContentAsString()).doesNotContain(UNKNOWN);
        assertThat(output).doesNotContain("Unhandled exception");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth2/", "/connect/", "/.well-known/", "/actuator/"})
    void unknownPathInAuthorizationServerOrLoginChainAnswers404(String prefix) throws Exception {
        mockMvc.perform(get(prefix + UNKNOWN).with(signedIn()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Not Found"));
    }

    @Test
    void disabledParEndpointAnswers404() throws Exception {
        mockMvc.perform(post("/oauth2/par").header("Authorization", furchertChBasic())
                        .param("response_type", "code").param("client_id", "furchert-ch"))
                .andExpect(status().isNotFound());
    }

    @Test
    void unsupportedMethodAnswers405WithAllow() throws Exception {
        MvcResult r = mockMvc.perform(patch("/api/v1/users/1").with(admin()))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().exists("Allow"))
                .andExpect(jsonPath("$.error").value("Method Not Allowed"))
                .andReturn();
        assertThat(r.getResponse().getHeader("Allow")).contains("PUT");
    }

    @Test
    void unsupportedMediaTypeAnswers415() throws Exception {
        mockMvc.perform(post("/api/v1/users").with(admin()).contentType(MediaType.TEXT_PLAIN).content("x"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.error").value("Unsupported Media Type"));
    }

    @Test
    void unacceptableMediaTypeAnswers406() throws Exception {
        // The JSON error body cannot be written for Accept: application/xml either; the status is what counts.
        mockMvc.perform(get("/api/v1/users").with(admin()).accept(MediaType.APPLICATION_XML))
                .andExpect(status().isNotAcceptable());
    }

    @Test
    void anonymousCallersStillGetTheSecurityChainAnswer() throws Exception {
        mockMvc.perform(get("/api/v1/" + UNKNOWN)).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/.well-known/" + UNKNOWN)).andExpect(status().isFound());
    }

    @Test
    void tokenEndpointStillAnswersUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token").header("Authorization", furchertChBasic())
                        .param("grant_type", "password").param("username", "x").param("password", "y"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }
}
