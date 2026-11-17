package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.exception.InvalidInputException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {

    private static final PasswordBlocklist BLOCKLIST = new PasswordBlocklist();
    private final PasswordPolicy policy = new PasswordPolicy(BLOCKLIST);

    private PasswordPolicy.Rule rule(String password) {
        return policy.firstFailedRule(password, "alice", "alice.wonder@example.test");
    }

    @Test
    void acceptsALongUnlistedPassphrase() {
        assertThat(rule("correct horse battery staple")).isNull();
        assertThat(rule("k9-unlisted-q7z")).isNull();                          // exactly 15
        assertThat(rule("ü".repeat(36))).isNull();                              // 36 characters, 72 bytes
    }

    @Test
    void tooShort_countsCharactersNotBytes() {
        assertThat(rule("x".repeat(14))).isEqualTo(PasswordPolicy.Rule.TOO_SHORT);
        assertThat(rule("ü".repeat(14))).isEqualTo(PasswordPolicy.Rule.TOO_SHORT);  // 28 bytes, 14 characters
        assertThat(rule("🔒".repeat(14))).isEqualTo(PasswordPolicy.Rule.TOO_SHORT); // 14 code points
    }

    @Test
    void tooLong_isMeasuredInUtf8Bytes() {
        assertThat(rule("x".repeat(73))).isEqualTo(PasswordPolicy.Rule.TOO_LONG);
        assertThat(rule("ü".repeat(37))).isEqualTo(PasswordPolicy.Rule.TOO_LONG);    // 37 characters, 74 bytes
    }

    @ParameterizedTest
    @ValueSource(strings = {"!qazxsw2#edcvfr4", "!QAZXSW2#EDCVFR4", "  !qazxsw2#edcvfr4  "})
    void tooCommon_ignoresCaseAndSurroundingWhitespace(String password) {
        assertThat(rule(password)).isEqualTo(PasswordPolicy.Rule.TOO_COMMON);
    }

    @Test
    void matchesAccount_usernameOrEmailParts() {
        PasswordPolicy.Rule r = policy.firstFailedRule("Longusername-2026", "longusername-2026", "x@example.test");
        assertThat(r).isEqualTo(PasswordPolicy.Rule.MATCHES_ACCOUNT);
        assertThat(rule("alice.wonder@example.test")).isEqualTo(PasswordPolicy.Rule.MATCHES_ACCOUNT);
        assertThat(policy.firstFailedRule("alice.wonderland", "a", "Alice.Wonderland@example.test"))
                .isEqualTo(PasswordPolicy.Rule.MATCHES_ACCOUNT);                  // e-mail local part
        assertThat(policy.firstFailedRule("mail.example.test", "a", "a@mail.example.test"))
                .isEqualTo(PasswordPolicy.Rule.MATCHES_ACCOUNT);                  // e-mail domain
        assertThat(rule("alice.wonder@example.test and more")).isNull();         // containing is fine
    }

    @Test
    void check_throwsInvalidInputNamingTheRuleUnderTheRequestField() {
        assertThatThrownBy(() -> policy.check("newPassword", "tiny-pw", "alice", "a@example.test"))
                .isInstanceOfSatisfying(InvalidInputException.class, e -> {
                    assertThat(e.getMessage()).isEqualTo("password does not meet the policy");
                    assertThat(e.getDetails()).isEqualTo(Map.of("newPassword", PasswordPolicy.Rule.TOO_SHORT.message));
                    assertThat(e.getDetails().get("newPassword")).doesNotContain("tiny-pw");   // never echoes input
                });
        assertThatCode(() -> policy.check("password", "correct horse battery staple", "alice", "a@example.test"))
                .doesNotThrowAnyException();
    }
}
