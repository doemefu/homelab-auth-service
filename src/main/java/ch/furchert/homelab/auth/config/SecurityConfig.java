package ch.furchert.homelab.auth.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String LOGIN_URL = "/login";
    private static final String ADMIN = "ADMIN";

    /**
     * Chain 2: stateless resource-server for the admin REST API.
     * CSRF is not required: Bearer tokens are sent via the Authorization header,
     * which browsers cannot forge cross-site. ignoringRequestMatchers covers all
     * requests in this chain without calling disable() (satisfies CodeQL).
     */
    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/api/v1/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/users").hasRole(ADMIN)
                        .requestMatchers(HttpMethod.PUT, "/api/v1/users/**").hasRole(ADMIN)
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/users/**").hasRole(ADMIN)
                        // /api/v1/clients/** uses method-level @PreAuthorize on the controller
                        // (role ADMIN OR scope clients:admin). The filter chain only enforces
                        // authentication; method security enforces the exact rule.
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .exceptionHandling(ex -> ex
                        // HttpStatusEntryPoint calls response.setStatus(), not sendError() — it
                        // never marks the response as "in error", so Boot's /error rendering
                        // (and our catch-all fix above) never triggers and the body stays empty
                        // (#77). Call sendError() directly for the same fixed 401, routed through
                        // the same /error rendering as every other endpoint.
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(request -> true));

        return http.build();
    }

    /**
     * Chain 3: stateful form-login chain for the OIDC login page and actuator.
     * CSRF is enabled (default) to protect the session-based login form.
     */
    @Bean
    @Order(3)
    public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher(LOGIN_URL, "/actuator/**", "/swagger-ui.html", "/swagger-ui/**", "/api-docs", "/api-docs/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(LOGIN_URL, "/actuator/health", "/actuator/info").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage(LOGIN_URL)
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                );

        return http.build();
    }

    /**
     * Chain 999: catch-all — deny everything not matched by an earlier chain.
     * This covers paths like /swagger-ui.html, /api-docs, and static assets.
     * <p>
     * Boot renders every {@code sendError()} (4xx/5xx from any chain, including
     * this one) by forwarding the request to {@code /error} as an ERROR dispatch.
     * Security's filter chain runs for ERROR dispatches too (default
     * {@code spring.security.filter.dispatcher-types}), so without the
     * exemptions below that forward was itself denied by this catch-all,
     * collapsing every error response into an empty 403 (#77).
     */
    @Bean
    @Order(999)
    public SecurityFilterChain catchAllSecurityFilterChain(HttpSecurity http) {
        http
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().denyAll())
                // The ERROR-dispatch forward to /error keeps the original HTTP method
                // (e.g. a CSRF-rejected POST /login). This chain has CSRF enabled by
                // default and is re-entered for the forward, so without this exemption
                // CsrfFilter rejects again and the response collapses back to the
                // empty-body 403 that made browsers download error responses (#77).
                .csrf(csrf -> csrf.ignoringRequestMatchers("/error"));
        return http.build();
    }

    /**
     * DelegatingPasswordEncoder supports {bcrypt}, {noop}, etc. prefixes used
     * for OIDC client secrets, while still matching legacy BCrypt user password
     * hashes stored without a prefix (via setDefaultPasswordEncoderForMatches).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder encoder =
                (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
        encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return encoder;
    }

    /**
     * Emits both ROLE_* authorities (from the "role" claim used by user JWTs) and
     * SCOPE_* authorities (from the standard "scope" claim used by client_credentials
     * tokens). Both converters always return an empty collection (never null) when
     * the corresponding claim is absent.
     */
    static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
        // default: reads "scope" / "scp", prefix "SCOPE_"

        JwtGrantedAuthoritiesConverter rolesConverter = new JwtGrantedAuthoritiesConverter();
        rolesConverter.setAuthoritiesClaimName("role");
        rolesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            Collection<GrantedAuthority> scopes = scopesConverter.convert(jwt);
            Collection<GrantedAuthority> roles = rolesConverter.convert(jwt);
            authorities.addAll(scopes);
            authorities.addAll(roles);
            return authorities;
        });
        return converter;
    }
}
