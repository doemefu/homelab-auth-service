package ch.furchert.homelab.auth.controller;

import ch.furchert.homelab.auth.dto.CreateDeviceClientRequest;
import ch.furchert.homelab.auth.dto.DeviceClientCreatedResponse;
import ch.furchert.homelab.auth.dto.DeviceClientResponse;
import ch.furchert.homelab.auth.service.DeviceClientService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Admin API for IoT device OAuth2 clients. Authorization rule:
 * <ul>
 *   <li>{@code hasRole('ADMIN')} — human administrator JWT (auth_code flow).</li>
 *   <li>{@code hasAuthority('SCOPE_clients:admin')} — service-to-service calls from
 *       device-service (client_credentials flow with the clients:admin scope).</li>
 * </ul>
 * <p>
 * Security note: the create() response body contains a plaintext client secret
 * returned exactly once. Do not log the response body. Sentry is configured
 * (application.yaml) without HTTP body capture, so default breadcrumbs are safe.
 */
@RestController
@RequestMapping("/api/v1/clients")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_clients:admin')")
public class DeviceClientController {

    private final DeviceClientService deviceClientService;

    @PostMapping
    public ResponseEntity<DeviceClientCreatedResponse> create(@Valid @RequestBody CreateDeviceClientRequest req) {
        DeviceClientCreatedResponse created =
                deviceClientService.create(req.clientId(), req.description());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @GetMapping
    public List<DeviceClientResponse> list() {
        return deviceClientService.list();
    }

    @GetMapping("/{clientId}")
    public DeviceClientResponse get(@PathVariable String clientId) {
        return deviceClientService.get(clientId);
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<Void> delete(@PathVariable String clientId) {
        deviceClientService.delete(clientId);
        return ResponseEntity.noContent().build();
    }
}
