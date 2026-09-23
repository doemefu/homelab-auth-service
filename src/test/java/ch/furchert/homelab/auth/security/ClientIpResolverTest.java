package ch.furchert.homelab.auth.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    @Test
    void usesCfConnectingIpWhenValidIpv4() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.42.0.7");
        req.addHeader("CF-Connecting-IP", " 203.0.113.7 ");

        ClientIpResolver.ResolvedIp ip = ClientIpResolver.resolve(req);

        assertThat(ip.ip()).isEqualTo("203.0.113.7");
        assertThat(ip.source()).isEqualTo("cf-connecting-ip");
    }

    @Test
    void usesCfConnectingIpWhenValidIpv6() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("CF-Connecting-IP", "2001:db8::1");

        ClientIpResolver.ResolvedIp ip = ClientIpResolver.resolve(req);

        assertThat(ip.source()).isEqualTo("cf-connecting-ip");
        assertThat(ip.ip()).isEqualTo("2001:db8:0:0:0:0:0:1");
    }

    @Test
    void fallsBackToRemoteAddrWithoutHeader() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.42.0.7");

        ClientIpResolver.ResolvedIp ip = ClientIpResolver.resolve(req);

        assertThat(ip.ip()).isEqualTo("10.42.0.7");
        assertThat(ip.source()).isEqualTo("remote-addr");
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "localhost", "1.2.3", "256.1.1.1", "1.2.3.4:80", "fe80::1%eth0",
            "1.2.3.4, 5.6.7.8", "", "  ", "::g"})
    void invalidHeaderFallsBackToRemoteAddr(String header) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.42.0.7");
        req.addHeader("CF-Connecting-IP", header);

        ClientIpResolver.ResolvedIp ip = ClientIpResolver.resolve(req);

        assertThat(ip.source()).isEqualTo("remote-addr");
        assertThat(ip.ip()).isEqualTo("10.42.0.7");
    }

    @Test
    void unparseableRemoteAddrGivesNullIp() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("not-an-ip");

        ClientIpResolver.ResolvedIp ip = ClientIpResolver.resolve(req);

        assertThat(ip.ip()).isNull();
        assertThat(ip.source()).isEqualTo("remote-addr");
    }

    @ParameterizedTest
    @ValueSource(strings = {"dead:beef", "cafe::babe::1", "abc:def", "example.invalid", "a.b.c.d"})
    void hostnameLikeValuesAreRejectedWithoutResolution(String value) {
        // Values that look like hosts or pass the character filter but are not valid IP literals
        // must be rejected by pure parsing: InetAddress.ofLiteral never performs a DNS lookup.
        assertThat(ClientIpResolver.normalize(value)).isNull();
    }

    @Test
    void ipv4MappedIpv6LiteralIsAccepted() {
        assertThat(ClientIpResolver.normalize("::ffff:203.0.113.7")).isEqualTo("203.0.113.7");
    }
}
