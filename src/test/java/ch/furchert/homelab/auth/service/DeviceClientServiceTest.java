package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.dto.DeviceClientCreatedResponse;
import ch.furchert.homelab.auth.exception.ResourceConflictException;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeviceClientServiceTest {

    @Mock
    RegisteredClientRepository registeredClientRepository;
    @Mock
    JdbcTemplate jdbcTemplate;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    ClientKindLookup clientKindLookup;

    private OidcClientProperties properties;

    @InjectMocks
    private DeviceClientService service;

    @BeforeEach
    void setUp() {
        properties = new OidcClientProperties();
        properties.getDeviceClients().setAccessTokenTtlSeconds(3600);
        properties.getDeviceClients().setAllowedScopes(List.of("mqtt:pub", "mqtt:sub"));
        service = new DeviceClientService(
                registeredClientRepository, jdbcTemplate, passwordEncoder, clientKindLookup, properties);
    }

    @Test
    void create_returnsPlaintextSecretAndPersistsClientKindDevice() {
        when(registeredClientRepository.findByClientId("terra1")).thenReturn(null);
        when(passwordEncoder.encode(any())).thenAnswer(inv -> "{bcrypt}$2a$10$hash-of-" + inv.getArgument(0));

        DeviceClientCreatedResponse response = service.create("terra1", "Greenhouse 1");

        assertThat(response.clientId()).isEqualTo("terra1");
        assertThat(response.clientSecret()).isNotBlank();
        // Plaintext secret is base64url-encoded 32 random bytes ~> 43 chars without padding
        assertThat(response.clientSecret()).hasSizeBetween(40, 45);
        assertThat(response.scopes()).containsExactlyInAnyOrder("mqtt:pub", "mqtt:sub");
        assertThat(response.createdAt()).isNotNull();

        ArgumentCaptor<RegisteredClient> clientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(registeredClientRepository).save(clientCaptor.capture());
        RegisteredClient saved = clientCaptor.getValue();
        assertThat(saved.getClientId()).isEqualTo("terra1");
        assertThat(saved.getClientSecret()).startsWith("{bcrypt}");
        assertThat(saved.getScopes()).containsExactlyInAnyOrder("mqtt:pub", "mqtt:sub");

        verify(jdbcTemplate).update(
                "UPDATE oauth2_registered_client SET client_kind = ? WHERE id = ?",
                "device", saved.getId());
        verify(clientKindLookup).invalidate(saved.getId());
    }

    @Test
    void create_failsFastWhenEncoderOmitsBcryptPrefix() {
        when(registeredClientRepository.findByClientId("terra1")).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("missing-prefix-hash");

        assertThatThrownBy(() -> service.create("terra1", null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("{bcrypt} prefix");

        verify(registeredClientRepository, never()).save(any());
        verify(jdbcTemplate, never()).update(any(String.class), any(), any());
    }

    @Test
    void create_rejectsDuplicateClientId() {
        RegisteredClient existing = RegisteredClient.withId("x").clientId("terra1")
                .clientSecret("{noop}s").clientAuthenticationMethod(
                        org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        when(registeredClientRepository.findByClientId("terra1")).thenReturn(existing);

        assertThatThrownBy(() -> service.create("terra1", null))
                .isInstanceOf(ResourceConflictException.class);

        verify(registeredClientRepository, never()).save(any());
    }

    @Test
    void delete_isIdempotentWhenMissing() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("ghost"), eq("device")))
                .thenThrow(new EmptyResultDataAccessException(1));

        service.delete("ghost");

        verify(jdbcTemplate, never()).update(any(String.class), eq("ghost"));
    }

    @Test
    void delete_doesNotTouchSsoClient() {
        // SELECT returns no row because the client_kind='device' filter excludes the SSO row.
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("grafana"), eq("device")))
                .thenThrow(new EmptyResultDataAccessException(1));

        service.delete("grafana");

        // CRITICAL: no DELETE FROM oauth2_authorization is issued for the SSO client.
        verify(jdbcTemplate, never()).update(
                eq("DELETE FROM oauth2_authorization WHERE registered_client_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                eq("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                eq("DELETE FROM oauth2_registered_client WHERE id = ?"),
                any(Object[].class));
    }

    @Test
    void delete_revokesAuthorizationsAndDeletesRowForDeviceClient() {
        String internalId = "uuid-1";
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("terra1"), eq("device")))
                .thenReturn(internalId);

        service.delete("terra1");

        verify(jdbcTemplate).update(
                "DELETE FROM oauth2_authorization WHERE registered_client_id = ?", internalId);
        verify(jdbcTemplate).update(
                "DELETE FROM oauth2_authorization_consent WHERE registered_client_id = ?", internalId);
        verify(jdbcTemplate).update(
                "DELETE FROM oauth2_registered_client WHERE id = ?", internalId);
        verify(clientKindLookup).invalidate(internalId);
    }

    @Test
    void get_unknownClient_throws404() {
        when(jdbcTemplate.queryForObject(any(String.class),
                any(),
                eq("device"), eq("ghost")))
                .thenThrow(new EmptyResultDataAccessException(1));

        assertThatThrownBy(() -> service.get("ghost"))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
