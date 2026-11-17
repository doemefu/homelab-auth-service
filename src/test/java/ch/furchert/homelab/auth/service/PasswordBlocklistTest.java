package ch.furchert.homelab.auth.service;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** The bundled list is the documented generated file: its body matches the header's sha256 and count. */
class PasswordBlocklistTest {

    private static String header(List<String> lines, String key) {
        Pattern p = Pattern.compile("^# " + Pattern.quote(key) + ":\\s+(\\S+)$");
        return lines.stream().map(p::matcher).filter(Matcher::matches).map(m -> m.group(1)).findFirst().orElseThrow();
    }

    @Test
    void bodyMatchesTheRecordedSha256AndCount() throws IOException, NoSuchAlgorithmException {
        String content = new ClassPathResource(PasswordBlocklist.RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        List<String> lines = content.lines().toList();
        List<String> body = lines.stream().filter(l -> !l.startsWith("#")).toList();
        // sha256 as `grep -v '^#' password-blocklist.txt | sha256sum` prints it (one entry per line, final newline)
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest((String.join("\n", body) + "\n").getBytes(StandardCharsets.UTF_8));

        assertThat(HexFormat.of().formatHex(digest)).isEqualTo(header(lines, "body-sha256"));
        assertThat(body).hasSize(Integer.parseInt(header(lines, "entries")));
        assertThat(header(lines, "source-commit")).matches("[0-9a-f]{40}");
        assertThat(content).contains("MIT License").contains("Copyright (c) 2018 Daniel Miessler");
    }

    @Test
    void entriesAreNormalisedAndInsideTheLengthBand() throws IOException {
        String content = new ClassPathResource(PasswordBlocklist.RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        assertThat(content.lines().filter(l -> !l.startsWith("#"))).allSatisfy(entry -> {
            assertThat(entry).isEqualTo(PasswordPolicy.normalize(entry));
            assertThat(entry.getBytes(StandardCharsets.UTF_8).length).isBetween(PasswordPolicy.MIN_CHARACTERS,
                    PasswordPolicy.MAX_UTF8_BYTES);
        });
    }

    @Test
    void loadsEveryEntry() {
        PasswordBlocklist blocklist = new PasswordBlocklist();
        assertThat(blocklist.size()).isGreaterThan(10_000);
        assertThat(blocklist.contains("!qazxsw2#edcvfr4")).isTrue();
        assertThat(blocklist.contains("not-a-listed-passphrase-7f3c")).isFalse();
    }
}
