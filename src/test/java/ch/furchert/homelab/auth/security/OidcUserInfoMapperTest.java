package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class OidcUserInfoMapperTest {

    UserRepository userRepository;
    OidcUserInfoMapper mapper;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        mapper = new OidcUserInfoMapper(userRepository);
    }

    private OidcUserInfoAuthenticationContext contextFor(String username) {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getPrincipalName()).thenReturn(username);
        OidcUserInfoAuthenticationContext context = mock(OidcUserInfoAuthenticationContext.class);
        when(context.getAuthorization()).thenReturn(authorization);
        return context;
    }

    @Test
    void mapsSubjectFromUsername() {
        User user = userWith("dominic", "dominic@furchert.ch", Role.USER);
        when(userRepository.findByUsername("dominic")).thenReturn(Optional.of(user));

        OidcUserInfo info = mapper.apply(contextFor("dominic"));

        assertThat(info.getSubject()).isEqualTo("dominic");
    }

    @Test
    void mapsEmail() {
        User user = userWith("dominic", "dominic@furchert.ch", Role.USER);
        when(userRepository.findByUsername("dominic")).thenReturn(Optional.of(user));

        OidcUserInfo info = mapper.apply(contextFor("dominic"));

        assertThat(info.getEmail()).isEqualTo("dominic@furchert.ch");
    }

    @Test
    void mapsPreferredUsername() {
        User user = userWith("dominic", "dominic@furchert.ch", Role.USER);
        when(userRepository.findByUsername("dominic")).thenReturn(Optional.of(user));

        OidcUserInfo info = mapper.apply(contextFor("dominic"));

        assertThat(info.getClaims().get("preferred_username")).isEqualTo("dominic");
    }

    @Test
    void mapsRoleClaimForUser() {
        User user = userWith("dominic", "dominic@furchert.ch", Role.USER);
        when(userRepository.findByUsername("dominic")).thenReturn(Optional.of(user));

        OidcUserInfo info = mapper.apply(contextFor("dominic"));

        assertThat(info.getClaims().get("role")).isEqualTo("USER");
    }

    @Test
    void mapsRoleClaimForAdmin() {
        User user = userWith("admin", "admin@furchert.ch", Role.ADMIN);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));

        OidcUserInfo info = mapper.apply(contextFor("admin"));

        assertThat(info.getClaims().get("role")).isEqualTo("ADMIN");
    }

    @Test
    void throwsWhenUserNotFound() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> mapper.apply(contextFor("ghost")))
            .isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class);
    }

    private User userWith(String username, String email, Role role) {
        User u = new User();
        u.setUsername(username);
        u.setEmail(email);
        u.setRole(role);
        return u;
    }
}
