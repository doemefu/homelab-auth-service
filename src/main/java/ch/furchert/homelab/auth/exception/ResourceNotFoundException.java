package ch.furchert.homelab.auth.exception;

import java.util.Map;

/** Optional {@code details} are keyed by request field and hold constant text, never request input. */
public class ResourceNotFoundException extends RuntimeException {

    private final Map<String, String> details;

    public ResourceNotFoundException(String message) {
        this(message, null);
    }

    public ResourceNotFoundException(String message, Map<String, String> details) {
        super(message);
        this.details = details == null ? null : Map.copyOf(details);
    }

    public Map<String, String> getDetails() {
        return details;
    }
}
