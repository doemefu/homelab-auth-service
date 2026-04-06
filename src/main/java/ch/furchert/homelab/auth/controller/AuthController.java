package ch.furchert.homelab.auth.controller;

import ch.furchert.homelab.auth.dto.LoginRequest;
import ch.furchert.homelab.auth.dto.LoginResponse;
import ch.furchert.homelab.auth.dto.RefreshRequest;
import ch.furchert.homelab.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal String username) {
        authService.logout(username);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok(authService.getJwks());
    }
}
