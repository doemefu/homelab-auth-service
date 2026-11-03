package ch.furchert.homelab.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

/**
 * Client-authentication error response (#104). A throttled attempt gets {@code 429} with
 * {@code Retry-After} and {@code Cache-Control: no-store}. Every other failure is answered exactly like
 * Spring Authorization Server's built-in handler in {@code OAuth2ClientAuthenticationFilter} (7.1.2):
 * clear the context, {@code 401} for {@code invalid_client} else {@code 400}, body with the error code
 * only.
 */
public class ClientAuthenticationErrorHandler implements AuthenticationFailureHandler {

    private final HttpMessageConverter<OAuth2Error> errorConverter = new OAuth2ErrorHttpMessageConverter();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        SecurityContextHolder.clearContext();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        if (exception instanceof ThrottlingClientSecretAuthenticationProvider.ThrottledException throttled) {
            httpResponse.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            httpResponse.getHeaders().set(HttpHeaders.RETRY_AFTER,
                    Long.toString(Math.max(1, (throttled.getRetryAfter().toMillis() + 999) / 1000)));
            httpResponse.getHeaders().setCacheControl("no-store");
            errorConverter.write(throttled.getError(), null, httpResponse);
            return;
        }
        OAuth2Error error = exception instanceof OAuth2AuthenticationException oauth2
                ? oauth2.getError() : new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);
        httpResponse.setStatusCode(OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())
                ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST);
        // Don't send the error description or URI back to the client, like the built-in handler.
        errorConverter.write(new OAuth2Error(error.getErrorCode()), null, httpResponse);
    }
}
