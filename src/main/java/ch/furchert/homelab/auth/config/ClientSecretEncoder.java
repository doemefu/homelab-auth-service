package ch.furchert.homelab.auth.config;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The client-secret encoder ({@link PasswordEncoders#clientSecrets()}) as a bean of its own type. It is
 * deliberately not a {@link PasswordEncoder} bean: a second bean of that type would make Spring Security's
 * by-type lookups (the global {@code DaoAuthenticationProvider}, the authorization server's client
 * authentication) ambiguous or silently fall back to defaults.
 */
public record ClientSecretEncoder(PasswordEncoder encoder) {
}
