package ch.furchert.homelab.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Form-login half of the throttle (#104). Sits in the login chain directly before
 * {@code UsernamePasswordAuthenticationFilter} (so after CSRF) and reads the username exactly as that
 * filter does. A throttled attempt is redirected to {@code /login?throttled} before any credential
 * check, the same way for existing and unknown usernames. The outcome of an admitted attempt comes from
 * {@link LoginThrottle}'s authentication-event listener via a request attribute.
 * <p>
 * Never a Spring bean: Boot would register it as a servlet filter for every request.
 */
public class LoginThrottleFilter extends OncePerRequestFilter {

    private final LoginThrottle throttle;
    private final RequestMatcher loginPost;

    public LoginThrottleFilter(LoginThrottle throttle, String loginUrl) {
        this.throttle = throttle;
        this.loginPost = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginUrl);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!throttle.isEnabled() || !loginPost.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        // Same parameter and trimming as UsernamePasswordAuthenticationFilter (query string or body).
        String username = request.getParameter("username");
        LoginThrottle.Admission admission = throttle.acquireLogin(username == null ? "" : username.trim(),
                ClientIpResolver.resolve(request).ip());
        if (!admission.admitted()) {
            response.sendRedirect(request.getContextPath() + "/login?throttled");
            return;
        }
        try {
            chain.doFilter(request, response);
        } finally {
            Object outcome = request.getAttribute(LoginThrottle.OUTCOME_ATTRIBUTE);
            throttle.complete(admission.ticket(),
                    outcome instanceof LoginThrottle.Outcome o ? o : LoginThrottle.Outcome.NONE);
        }
    }
}
