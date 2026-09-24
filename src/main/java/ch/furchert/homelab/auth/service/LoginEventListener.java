package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.security.ClientIpResolver;
import ch.furchert.homelab.auth.security.UsernameHmac;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.UUID;

/**
 * Captures form-login attempts from Spring Security's authentication events (docs/060 §7.6).
 * <p>
 * Only {@link UsernamePasswordAuthenticationToken}s are recorded — JWT-bearer and OAuth2 client
 * authentications publish events too and are ignored. Request data (IP, user agent) is read
 * synchronously on the request thread, then the immutable {@link LoginEvent} goes to
 * {@link LoginEventRecorder}. Outcome mapping: success → {@code success};
 * {@link DisabledException} (users.status != ACTIVE, thrown before the password check) →
 * {@code locked}; any other failure → {@code failure}. A login never fails because of this class.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginEventListener {

    static final int MAX_USER_AGENT_LENGTH = 512;

    private final LoginEventFeature feature;
    private final UsernameHmac usernameHmac;
    private final LoginEventRecorder recorder;

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        capture(event.getAuthentication(), event.getTimestamp(), LoginEvent.SUCCESS);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String outcome = event.getException() instanceof DisabledException ? LoginEvent.LOCKED : LoginEvent.FAILURE;
        capture(event.getAuthentication(), event.getTimestamp(), outcome);
    }

    private void capture(Authentication authentication, long timestamp, String outcome) {
        if (!feature.isEnabled() || !(authentication instanceof UsernamePasswordAuthenticationToken)) {
            return;
        }
        try {
            // Success: the authenticated name (== submitted name, lookups are exact).
            // Failure: the unauthenticated token's principal is the submitted username.
            String username = authentication.getName();
            HttpServletRequest request = currentRequest();
            ClientIpResolver.ResolvedIp ip = request != null
                    ? ClientIpResolver.resolve(request)
                    : new ClientIpResolver.ResolvedIp(null, ClientIpResolver.SOURCE_REMOTE);
            String userAgent = request != null ? truncate(request.getHeader(HttpHeaders.USER_AGENT)) : null;

            recorder.submit(new LoginEvent(
                    UUID.randomUUID(),
                    Instant.ofEpochMilli(timestamp),
                    outcome,
                    ip.ip(),
                    ip.source(),
                    usernameHmac.hash(username),
                    LoginEvent.SUCCESS.equals(outcome) ? username : null,
                    userAgent));
        } catch (RuntimeException e) {
            log.warn("Could not capture login event: {}", e.getClass().getSimpleName());
        }
    }

    private static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servlet ? servlet.getRequest() : null;
    }

    private static String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= MAX_USER_AGENT_LENGTH ? value : value.substring(0, MAX_USER_AGENT_LENGTH);
    }
}
