package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Loads users for form login. As the {@link UserDetailsPasswordService}, it also stores the re-encoded hash when
 * the login provider finds an outdated one (lower bcrypt cost, no prefix): every active user's hash moves to the
 * current cost at the next successful login (#150).
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserRepository userRepository;

    @Override
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        ch.furchert.homelab.auth.entity.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        boolean enabled = "ACTIVE".equals(user.getStatus());
        return new User(
                user.getUsername(),
                user.getPasswordHash(),
                enabled,
                true,
                true,
                true,
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }

    @Override
    @Transactional
    @NonNull
    public UserDetails updatePassword(@NonNull UserDetails user, @Nullable String newPassword) {
        userRepository.findByUsername(user.getUsername()).ifPresent(entity -> {
            entity.setPasswordHash(newPassword);
            userRepository.save(entity);
        });
        return User.withUserDetails(user).password(newPassword).build();
    }
}
