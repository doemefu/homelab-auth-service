package ch.furchert.homelab.auth.controller;

import ch.furchert.homelab.auth.config.SecurityConfig;
import ch.furchert.homelab.auth.dto.CreateDeviceClientRequest;
import ch.furchert.homelab.auth.dto.DeviceClientCreatedResponse;
import ch.furchert.homelab.auth.dto.DeviceClientResponse;
import ch.furchert.homelab.auth.exception.ResourceConflictException;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import ch.furchert.homelab.auth.service.DeviceClientService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DeviceClientController.class)
@Import(SecurityConfig.class)
class DeviceClientControllerTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @MockitoBean
    JwtDecoder jwtDecoder;
    @MockitoBean
    DeviceClientService deviceClientService;

    @Test
    void create_asAdmin_returns201WithPlaintextSecret() throws Exception {
        DeviceClientCreatedResponse created = new DeviceClientCreatedResponse(
                "terra1", "plain-secret-123", List.of("mqtt:pub", "mqtt:sub"), Instant.now());
        when(deviceClientService.create("terra1", "Greenhouse 1")).thenReturn(created);

        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateDeviceClientRequest("terra1", "Greenhouse 1"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId").value("terra1"))
                .andExpect(jsonPath("$.clientSecret").value("plain-secret-123"));
    }

    @Test
    void create_withScopeClientsAdmin_returns201() throws Exception {
        DeviceClientCreatedResponse created = new DeviceClientCreatedResponse(
                "terra2", "secret", List.of("mqtt:pub", "mqtt:sub"), Instant.now());
        when(deviceClientService.create(eq("terra2"), any())).thenReturn(created);

        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_clients:admin")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateDeviceClientRequest("terra2", null))))
                .andExpect(status().isCreated());
    }

    @Test
    void create_asPlainUser_returns403() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateDeviceClientRequest("terra1", null))))
                .andExpect(status().isForbidden());

        verifyNoInteractions(deviceClientService);
    }

    @Test
    void create_unauthenticated_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateDeviceClientRequest("terra1", null))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void create_withInvalidClientIdPattern_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"UPPER\",\"description\":null}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void create_withTooShortClientId_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"x\",\"description\":null}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void create_duplicateClientId_returns409() throws Exception {
        when(deviceClientService.create(eq("terra1"), any()))
                .thenThrow(new ResourceConflictException("exists"));

        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateDeviceClientRequest("terra1", null))))
                .andExpect(status().isConflict());
    }

    @Test
    void list_asAdmin_returns200() throws Exception {
        when(deviceClientService.list()).thenReturn(List.of(
                new DeviceClientResponse("terra1", "Greenhouse 1", Instant.now(),
                        List.of("mqtt:pub", "mqtt:sub"))));

        mockMvc.perform(get("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].clientId").value("terra1"));
    }

    @Test
    void get_unknown_returns404() throws Exception {
        when(deviceClientService.get("ghost"))
                .thenThrow(new ResourceNotFoundException("not found"));

        mockMvc.perform(get("/api/v1/clients/ghost")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNotFound());
    }

    @Test
    void delete_returns204AndCallsService() throws Exception {
        doNothing().when(deviceClientService).delete("terra1");

        mockMvc.perform(delete("/api/v1/clients/terra1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());

        verify(deviceClientService).delete("terra1");
    }

    @Test
    void delete_missing_returns204Idempotent() throws Exception {
        doNothing().when(deviceClientService).delete("ghost");

        mockMvc.perform(delete("/api/v1/clients/ghost")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());
    }

    @Test
    void delete_asPlainUser_returns403() throws Exception {
        mockMvc.perform(delete("/api/v1/clients/terra1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());

        verifyNoInteractions(deviceClientService);
    }
}
