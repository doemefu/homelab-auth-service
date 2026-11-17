package ch.furchert.homelab.auth.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(FieldError::getField,
                        fe -> fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "invalid",
                        (a, b) -> a));
        return ResponseEntity.badRequest().body(errorBody(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleMessageNotReadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(errorBody(HttpStatus.BAD_REQUEST, "Invalid request body", null));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(errorBody(HttpStatus.UNAUTHORIZED, "Unauthorized", null));
    }

    /**
     * {@code @PreAuthorize} failures raise AuthorizationDeniedException; legacy access
     * decisions raise AccessDeniedException. Both must return 403 — otherwise
     * the catch-all generic handler below maps them to 500.
     */
    @ExceptionHandler({AuthorizationDeniedException.class, AccessDeniedException.class})
    public ResponseEntity<Map<String, Object>> handleAuthorizationDenied(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(errorBody(HttpStatus.FORBIDDEN, "Forbidden", null));
    }

    /**
     * Fallback for any other {@link IllegalArgumentException}: a constant text, because its message may echo request
     * input or come from a library (#151). Expected rule failures throw {@link InvalidInputException} instead.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        log.debug("Request rejected: {}", ex.getClass().getSimpleName());
        return ResponseEntity.badRequest().body(errorBody(HttpStatus.BAD_REQUEST, "invalid request", null));
    }

    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(InvalidInputException ex) {
        return ResponseEntity.badRequest().body(errorBody(HttpStatus.BAD_REQUEST, ex.getMessage(), ex.getDetails()));
    }

    /** A non-numeric query parameter (e.g. {@code after=abc}) is a client error, not a 500. */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return ResponseEntity.badRequest()
                .body(errorBody(HttpStatus.BAD_REQUEST, "Invalid value for parameter '" + ex.getName() + "'", null));
    }

    @ExceptionHandler(LoginEventsDisabledException.class)
    public ResponseEntity<Map<String, Object>> handleLoginEventsDisabled(LoginEventsDisabledException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(errorBody(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage(), null));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(errorBody(HttpStatus.NOT_FOUND, ex.getMessage(), ex.getDetails()));
    }

    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(ResourceConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(errorBody(HttpStatus.CONFLICT, ex.getMessage(), ex.getDetails()));
    }

    /**
     * Last resort. Spring MVC request errors ({@link ErrorResponse}: no handler 404, unsupported method 405 with
     * {@code Allow}, unsupported media type 415, and others such as a missing parameter 400 or an upload size 413)
     * keep their own status and headers (#147). The message is the HTTP reason phrase, never the exception detail,
     * which echoes request input; a {@code ResponseStatusException}'s reason text is replaced the same way (nothing
     * throws it today). Everything else is unexpected: 500 and an ERROR log.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        if (ex instanceof ErrorResponse errorResponse) {
            HttpStatus status = HttpStatus.resolve(errorResponse.getStatusCode().value());
            if (status != null) {
                if (status.is5xxServerError()) {
                    log.error("Unhandled exception", ex);
                } else {
                    log.debug("Request error {}: {}", status.value(), ex.getClass().getSimpleName());
                }
                return ResponseEntity.status(status).headers(errorResponse.getHeaders())
                        .body(errorBody(status, status.getReasonPhrase(), null));
            }
        }
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorBody(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", null));
    }

    private Map<String, Object> errorBody(HttpStatus status, String message, Object details) {
        return details != null
                ? Map.of("status", status.value(), "error", message, "timestamp", Instant.now().toString(), "details", details)
                : Map.of("status", status.value(), "error", message, "timestamp", Instant.now().toString());
    }
}
