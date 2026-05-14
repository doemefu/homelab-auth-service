package ch.furchert.homelab.auth.exception;

public class ResourceConflictException extends RuntimeException {

    public ResourceConflictException(String message) {
        super(message);
    }
}
