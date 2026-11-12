package ch.furchert.homelab.auth.service;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * Commonly used passwords within the policy's length band, loaded once from {@code password-blocklist.txt}
 * (provenance, filter and licence in its header). Entries are lowercased and trimmed; lookups must pass the
 * candidate normalised the same way.
 */
@Component
public class PasswordBlocklist {

    static final String RESOURCE = "password-blocklist.txt";

    private final Set<String> entries;

    public PasswordBlocklist() {
        this.entries = Set.copyOf(load());
    }

    boolean contains(String normalized) {
        return entries.contains(normalized);
    }

    int size() {
        return entries.size();
    }

    private static Set<String> load() {
        Set<String> result = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ClassPathResource(RESOURCE).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty() && !line.startsWith("#")) {
                    result.add(line);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + RESOURCE, e);
        }
        if (result.isEmpty()) {
            throw new IllegalStateException(RESOURCE + " has no entries");
        }
        return result;
    }
}
