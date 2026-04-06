package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.RsaKeyProperties;
import ch.furchert.homelab.auth.dto.LoginRequest;
import ch.furchert.homelab.auth.dto.LoginResponse;
import ch.furchert.homelab.auth.entity.RefreshToken;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import ch.furchert.homelab.auth.repository.RefreshTokenRepository;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.security.JwtService;
import ch.furchert.homelab.auth.security.RsaKeyProvider;
import io.jsonwebtoken.security.Jwks;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final RsaKeyProvider rsaKeyProvider;
    private final RsaKeyProperties rsaKeyProperties;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        User user = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + auth.getName()));

        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String rawRefreshToken = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(hashToken(rawRefreshToken));
        refreshToken.setExpiresAt(Instant.now().plusMillis(rsaKeyProperties.getRefreshTokenExpiry()));
        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(accessToken, rawRefreshToken);
    }

    @Transactional
    public LoginResponse refresh(String rawRefreshToken) {
        String hashedToken = hashToken(rawRefreshToken);
        RefreshToken stored = refreshTokenRepository.findByToken(hashedToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(stored);
            throw new IllegalArgumentException("Refresh token expired");
        }

        User user = stored.getUser();

        // Rotate: delete old, issue new
        refreshTokenRepository.delete(stored);

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String newRawRefreshToken = UUID.randomUUID().toString();

        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setUser(user);
        newRefreshToken.setToken(hashToken(newRawRefreshToken));
        newRefreshToken.setExpiresAt(Instant.now().plusMillis(rsaKeyProperties.getRefreshTokenExpiry()));
        refreshTokenRepository.save(newRefreshToken);

        return new LoginResponse(newAccessToken, newRawRefreshToken);
    }

    @Transactional
    public void logout(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));
        refreshTokenRepository.deleteByUser(user);
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public Map<String, Object> getJwks() {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyProvider.getPublicKey();
        io.jsonwebtoken.security.RsaPublicJwk jwk = Jwks.builder()
                .key(publicKey)
                .id(JwtService.KEY_ID)
                .build();
        return Map.of("keys", java.util.List.of(jwk));
    }
}
