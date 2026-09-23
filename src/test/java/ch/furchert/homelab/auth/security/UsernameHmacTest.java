package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UsernameHmacTest {

    private static UsernameHmac withKey(String key) {
        LoginEventProperties props = new LoginEventProperties();
        props.setHmacKey(key);
        return new UsernameHmac(props);
    }

    @Test
    void rawMacMatchesKnownHmacSha256Vector() {
        // Well-known HMAC-SHA256 vector: key "key", message "The quick brown fox jumps over the lazy dog".
        assertThat(withKey("key").hmacHex("The quick brown fox jumps over the lazy dog"))
                .isEqualTo("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    }

    @Test
    void hashIsLowercaseHexOf64CharsAndNormalizesTrimAndCase() {
        UsernameHmac hmac = withKey("0123456789abcdef0123456789abcdef");
        String h = hmac.hash("alice");
        assertThat(h).matches("[0-9a-f]{64}");
        assertThat(hmac.hash("  Alice ")).isEqualTo(h);
        assertThat(hmac.hash("ALICE")).isEqualTo(h);
        assertThat(hmac.hash("bob")).isNotEqualTo(h);
    }

    @Test
    void differentKeysGiveDifferentHashes() {
        assertThat(withKey("0123456789abcdef0123456789abcdef").hash("alice"))
                .isNotEqualTo(withKey("fedcba9876543210fedcba9876543210").hash("alice"));
    }

    @Test
    void nullUsernameHashesAsEmptyString() {
        UsernameHmac hmac = withKey("0123456789abcdef0123456789abcdef");
        assertThat(hmac.hash(null)).isEqualTo(hmac.hash(""));
    }

    @Test
    void missingKeyFailsFast() {
        assertThatThrownBy(() -> withKey("").hash("alice")).isInstanceOf(IllegalStateException.class);
    }
}
