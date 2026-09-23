package ch.furchert.homelab.auth.exception;

/** The login-event outbox is not configured (missing env vars); mapped to HTTP 503. */
public class LoginEventsDisabledException extends RuntimeException {

    public LoginEventsDisabledException() {
        super("Login events are disabled");
    }
}
