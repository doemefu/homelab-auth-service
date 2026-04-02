package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.dto.CreateUserRequest;
import ch.furchert.homelab.auth.dto.LoginRequest;
import ch.furchert.homelab.auth.dto.LoginResponse;
import ch.furchert.homelab.auth.dto.RefreshRequest;
import ch.furchert.homelab.auth.repository.RefreshTokenRepository;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.service.UserService;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthIntegrationTest extends AbstractIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserService userService;
    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void cleanUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void jwksEndpoint_returnsPublicKey() throws Exception {
        mockMvc.perform(get("/api/v1/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    @Test
    void login_withValidCredentials_returnsAccessAndRefreshToken() throws Exception {
        userService.createUser(new CreateUserRequest("authuser", "auth@example.com", "password123", "USER"));

        LoginRequest request = new LoginRequest("authuser", "password123");
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void login_withWrongPassword_returnsUnauthorized() throws Exception {
        userService.createUser(new CreateUserRequest("authuser2", "auth2@example.com", "password123", "USER"));

        LoginRequest request = new LoginRequest("authuser2", "wrongpassword");
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void fullAuthFlow_loginRefreshLogout() throws Exception {
        userService.createUser(new CreateUserRequest("flowuser", "flow@example.com", "password123", "USER"));

        // Step 1: Login
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("flowuser", "password123"))))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse loginResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(), LoginResponse.class);
        String accessToken = loginResponse.accessToken();
        String refreshToken = loginResponse.refreshToken();

        // Step 2: Access protected endpoint with JWT — auth works (200/403/404 all mean auth passed)
        int statusCode = mockMvc.perform(get("/api/v1/users/1")
                        .header("Authorization", "Bearer " + accessToken))
                .andReturn().getResponse().getStatus();
        assertThat(statusCode).isIn(200, 403, 404);

        // Step 3: Refresh token
        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshRequest(refreshToken))))
                .andExpect(status().isOk())
                .andReturn();

        LoginResponse refreshResponse = objectMapper.readValue(
                refreshResult.getResponse().getContentAsString(), LoginResponse.class);
        assertThat(refreshResponse.accessToken()).isNotBlank();
        assertThat(refreshResponse.refreshToken()).isNotEqualTo(refreshToken); // rotated

        // Step 4: Old refresh token is now invalid
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshRequest(refreshToken))))
                .andExpect(status().isBadRequest());

        // Step 5: Logout with new access token
        String newAccessToken = refreshResponse.accessToken();
        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isNoContent());
    }
}
