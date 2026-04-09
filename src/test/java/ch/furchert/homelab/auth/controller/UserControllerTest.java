package ch.furchert.homelab.auth.controller;

import ch.furchert.homelab.auth.config.SecurityConfig;
import ch.furchert.homelab.auth.dto.CreateUserRequest;
import ch.furchert.homelab.auth.dto.UpdateUserRequest;
import ch.furchert.homelab.auth.dto.UserResponse;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import ch.furchert.homelab.auth.service.UserService;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
class UserControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    JwtDecoder jwtDecoder;

    @MockitoBean
    UserService userService;

    private UserResponse sampleUser() {
        return new UserResponse(1L, "testuser", "test@example.com", "USER", "ACTIVE",
                Instant.now(), Instant.now());
    }

    @Test
    void createUser_asAdmin_returns201() throws Exception {
        when(userService.createUser(any())).thenReturn(sampleUser());

        mockMvc.perform(post("/api/v1/users")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateUserRequest("testuser", "test@example.com", "password123", Role.USER))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void createUser_asUser_returns403() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateUserRequest("testuser", "test@example.com", "password123", Role.USER))))
                .andExpect(status().isForbidden());
    }

    @Test
    void createUser_unauthenticated_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateUserRequest("testuser", "test@example.com", "password123", Role.USER))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void createUser_withInvalidEmail_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"u\",\"email\":\"not-an-email\",\"password\":\"password123\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getUser_asOwner_returns200() throws Exception {
        when(userService.getUser(1L, "testuser", false)).thenReturn(sampleUser());

        mockMvc.perform(get("/api/v1/users/1")
                        .with(jwt().jwt(j -> j.subject("testuser"))
                                   .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void getUser_whenNotFound_returns404() throws Exception {
        when(userService.getUser(eq(99L), any(), eq(true)))
                .thenThrow(new ResourceNotFoundException("User not found: 99"));

        mockMvc.perform(get("/api/v1/users/99")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNotFound());
    }

    @Test
    void updateUser_asAdmin_returns200() throws Exception {
        when(userService.updateUser(eq(1L), any())).thenReturn(sampleUser());

        mockMvc.perform(put("/api/v1/users/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new UpdateUserRequest("newname", null, null, null))))
                .andExpect(status().isOk());
    }

    @Test
    void deleteUser_asAdmin_returns204() throws Exception {
        doNothing().when(userService).deleteUser(1L);

        mockMvc.perform(delete("/api/v1/users/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());
    }

    @Test
    void deleteUser_asUser_returns403() throws Exception {
        mockMvc.perform(delete("/api/v1/users/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }
}
