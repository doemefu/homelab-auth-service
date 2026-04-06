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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;
    @Mock private RsaKeyProvider rsaKeyProvider;
    @Mock private RsaKeyProperties rsaKeyProperties;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setRole("USER");
    }

    @Test
    void login_withValidCredentials_returnsTokens() {
        LoginRequest request = new LoginRequest("testuser", "password");
        Authentication auth = new UsernamePasswordAuthenticationToken("testuser", null);
        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken("testuser", "USER")).thenReturn("access-token");
        when(rsaKeyProperties.getRefreshTokenExpiry()).thenReturn(604800000L);
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        LoginResponse response = authService.login(request);

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isNotBlank();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void login_withInvalidCredentials_throwsBadCredentials() {
        LoginRequest request = new LoginRequest("testuser", "wrong");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void refresh_withValidToken_rotatesAndReturnsNewTokens() {
        String rawToken = "old-refresh-token";
        RefreshToken stored = new RefreshToken();
        stored.setToken("hashed-value");
        stored.setUser(user);
        stored.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));
        when(jwtService.generateAccessToken("testuser", "USER")).thenReturn("new-access-token");
        when(rsaKeyProperties.getRefreshTokenExpiry()).thenReturn(604800000L);
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        LoginResponse response = authService.refresh(rawToken);

        assertThat(response.accessToken()).isEqualTo("new-access-token");
        assertThat(response.refreshToken()).isNotBlank().isNotEqualTo(rawToken);
        verify(refreshTokenRepository).delete(stored);
    }

    @Test
    void refresh_withExpiredToken_throwsIllegalArgument() {
        String rawToken = "expired-token";
        RefreshToken stored = new RefreshToken();
        stored.setToken("hashed-value");
        stored.setUser(user);
        stored.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS));

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> authService.refresh(rawToken))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");

        verify(refreshTokenRepository).delete(stored);
    }

    @Test
    void refresh_withUnknownToken_throwsIllegalArgument() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("unknown"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    @Test
    void logout_deletesAllRefreshTokensForUser() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        authService.logout("testuser");

        verify(refreshTokenRepository).deleteByUser(user);
    }

    @Test
    void logout_withUnknownUser_throwsResourceNotFound() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.logout("ghost"))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
