package ch.furchert.homelab.auth.exception;

import java.util.Map;

/**
 * A request value that passed bean validation but breaks a service-side rule. Answered as {@code 400} with a
 * constant message and {@code details} keyed by the request field, so clients can show it next to that field.
 */
public class InvalidInputException extends RuntimeException {

    private final Map<String, String> details;

    public InvalidInputException(String message, Map<String, String> details) {
        super(message);
        this.details = Map.copyOf(details);
    }

    public Map<String, String> getDetails() {
        return details;
    }
}
