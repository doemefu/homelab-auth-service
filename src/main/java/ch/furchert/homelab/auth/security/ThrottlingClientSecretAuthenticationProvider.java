package ch.furchert.homelab.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;

/**
 * Client-authentication half of the throttle (#104): wraps Spring Authorization Server's
 * {@link ClientSecretAuthenticationProvider}, so it covers every endpoint that authenticates clients
 * with {@code client_secret_basic}/{@code client_secret_post} and keys on exactly the client id that
 * SAS authenticates. Only {@code invalid_client} failures of a registered client with the presented method
 * allowed count (a wrong secret); unknown ids and method mismatches cost no bcrypt check and never count. A throttled attempt fails before the secret is checked, with
 * {@link ThrottledException} (rendered as 429 by {@link ClientAuthenticationErrorHandler}).
 * <p>
 * Never a Spring bean: an AuthenticationProvider bean would join the global authentication manager.
 */
@Slf4j
public class ThrottlingClientSecretAuthenticationProvider implements AuthenticationProvider {

    /** Raised for a throttled client authentication; carries the Retry-After value. */
    public static class ThrottledException extends OAuth2AuthenticationException {
        private final Duration retryAfter;

        ThrottledException(Duration retryAfter) {
            super(new OAuth2Error("temporarily_unavailable",
                    "Too many failed client authentication attempts; retry later.", null));
            this.retryAfter = retryAfter;
        }

        public Duration getRetryAfter() {
            return retryAfter;
        }
    }

    private final ClientSecretAuthenticationProvider delegate;
    private final LoginThrottle throttle;
    private final RegisteredClientRepository registeredClients;

    public ThrottlingClientSecretAuthenticationProvider(ClientSecretAuthenticationProvider delegate,
                                                         LoginThrottle throttle,
                                                         RegisteredClientRepository registeredClients) {
        this.delegate = delegate;
        this.throttle = throttle;
        this.registeredClients = registeredClients;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!throttle.isEnabled() || !(authentication instanceof OAuth2ClientAuthenticationToken token)
                || !usesSecret(token)) {
            return delegate.authenticate(authentication);
        }
        String clientId = String.valueOf(token.getPrincipal());
        String secret = token.getCredentials() == null ? null : token.getCredentials().toString();
        LoginThrottle.Admission admission = throttle.acquireClient(clientId, currentClientIp(), secret);
        if (!admission.admitted()) {
            throw new ThrottledException(admission.retryAfter());
        }
        LoginThrottle.Outcome outcome = LoginThrottle.Outcome.NONE;
        try {
            Authentication result = delegate.authenticate(authentication);
            outcome = result != null ? LoginThrottle.Outcome.SUCCESS : LoginThrottle.Outcome.NONE;
            return result;
        } catch (OAuth2AuthenticationException e) {
            if (OAuth2ErrorCodes.INVALID_CLIENT.equals(e.getError().getErrorCode()) && secretWasChecked(token)) {
                outcome = LoginThrottle.Outcome.FAILURE;
            }
            throw e;
        } finally {
            throttle.complete(admission.ticket(), outcome);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }

    private static boolean usesSecret(OAuth2ClientAuthenticationToken token) {
        ClientAuthenticationMethod method = token.getClientAuthenticationMethod();
        return ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)
                || ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method);
    }

    /**
     * True when SAS got as far as the secret check: the client is registered and allows the presented
     * method. A method mismatch fails before any bcrypt work and must not count, or anyone could fill the
     * table with public client ids for free.
     */
    private boolean secretWasChecked(OAuth2ClientAuthenticationToken token) {
        try {
            RegisteredClient client = registeredClients.findByClientId(String.valueOf(token.getPrincipal()));
            return client != null && client.getClientAuthenticationMethods().contains(token.getClientAuthenticationMethod());
        } catch (DataAccessException e) {
            // Never let bookkeeping replace the authentication error; this failure is not counted.
            log.warn("Login throttle: client lookup failed ({}); failure not counted", e.getClass().getSimpleName());
            return false;
        }
    }

    private static String currentClientIp() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            HttpServletRequest request = servlet.getRequest();
            return ClientIpResolver.resolve(request).ip();
        }
        return null;
    }
}
