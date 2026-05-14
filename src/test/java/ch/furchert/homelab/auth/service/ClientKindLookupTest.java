package ch.furchert.homelab.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class ClientKindLookupTest {

    private JdbcTemplate jdbcTemplate;
    private ClientKindLookup lookup;

    @BeforeEach
    void setUp() {
        jdbcTemplate = mock(JdbcTemplate.class);
        lookup = new ClientKindLookup(jdbcTemplate);
    }

    @Test
    void cacheMissHitsDatabase() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("id-1")))
                .thenReturn("device");

        assertThat(lookup.lookup("id-1")).isEqualTo("device");
        assertThat(lookup.isDevice("id-1")).isTrue();
    }

    @Test
    void cacheHitSkipsDatabase() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("id-1")))
                .thenReturn("device");

        lookup.lookup("id-1");
        lookup.lookup("id-1");
        lookup.lookup("id-1");

        verify(jdbcTemplate, times(1))
                .queryForObject(any(String.class), eq(String.class), eq("id-1"));
    }

    @Test
    void invalidateForcesRefresh() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("id-1")))
                .thenReturn("device", "sso");

        assertThat(lookup.lookup("id-1")).isEqualTo("device");
        lookup.invalidate("id-1");
        assertThat(lookup.lookup("id-1")).isEqualTo("sso");
        assertThat(lookup.isDevice("id-1")).isFalse();
    }

    @Test
    void unknownIdReturnsNullAndIsNotDevice() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("missing")))
                .thenThrow(new EmptyResultDataAccessException(1));

        assertThat(lookup.lookup("missing")).isNull();
        assertThat(lookup.isDevice("missing")).isFalse();
    }

    @Test
    void ssoIsNotDevice() {
        when(jdbcTemplate.queryForObject(any(String.class), eq(String.class), eq("sso-1")))
                .thenReturn("sso");

        assertThat(lookup.isDevice("sso-1")).isFalse();
    }
}
