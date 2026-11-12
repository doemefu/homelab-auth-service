package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.exception.InvalidInputException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Rules for every password set through the API (#150), checked before it is hashed. Length first, a blocklist
 * of common passwords, and no copy of the account's own name or e-mail address; no composition rules and no
 * expiry (NIST SP 800-63B-4). The floor is 15 characters because the IdP is single-factor (#108).
 * Passwords written directly to the database bypass these rules.
 */
@Component
@RequiredArgsConstructor
public class PasswordPolicy {

    /** Minimum length in characters (Unicode code points). */
    public static final int MIN_CHARACTERS = 15;
    /** bcrypt reads at most 72 bytes; longer input is refused instead of being cut. */
    public static final int MAX_UTF8_BYTES = 72;

    static final String MESSAGE = "password does not meet the policy";

    /** The failed rule, named in the response's {@code details}. */
    enum Rule {
        TOO_SHORT("too short: use at least " + MIN_CHARACTERS + " characters"),
        TOO_LONG("too long: use at most " + MAX_UTF8_BYTES + " bytes (UTF-8)"),
        TOO_COMMON("too common: it appears in lists of breached passwords"),
        MATCHES_ACCOUNT("must not be the username or the e-mail address");

        final String message;

        Rule(String message) {
            this.message = message;
        }
    }

    private final PasswordBlocklist blocklist;

    /**
     * @param field    the request field, used as the {@code details} key ({@code password} or {@code newPassword})
     * @param password the new password
     * @param username the account's username
     * @param email    the account's e-mail address
     * @throws InvalidInputException naming the first failed rule
     */
    public void check(String field, String password, String username, String email) {
        Rule failed = firstFailedRule(password, username, email);
        if (failed != null) {
            throw new InvalidInputException(MESSAGE, Map.of(field, failed.message));
        }
    }

    Rule firstFailedRule(String password, String username, String email) {
        if (password.codePointCount(0, password.length()) < MIN_CHARACTERS) {
            return Rule.TOO_SHORT;
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_UTF8_BYTES) {
            return Rule.TOO_LONG;
        }
        String candidate = normalize(password);
        if (blocklist.contains(candidate)) {
            return Rule.TOO_COMMON;
        }
        if (accountWords(username, email).anyMatch(candidate::equals)) {
            return Rule.MATCHES_ACCOUNT;
        }
        return null;
    }

    /** Lowercase and trim only. No Unicode normalisation: it would change how existing passwords compare. */
    static String normalize(String value) {
        return value.strip().toLowerCase(Locale.ROOT);
    }

    private static Stream<String> accountWords(String username, String email) {
        Stream<String> emailParts = Stream.empty();
        if (email != null) {
            int at = email.lastIndexOf('@');
            emailParts = at < 0 ? Stream.of(email)
                    : Stream.of(email, email.substring(0, at), email.substring(at + 1));
        }
        return Stream.concat(Stream.of(username), emailParts)
                .filter(Objects::nonNull)
                .map(PasswordPolicy::normalize)
                .filter(word -> !word.isEmpty());
    }
}
