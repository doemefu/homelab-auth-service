package ch.furchert.homelab.auth.security;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Resolves the client IP for a login event (docs/060 §7.6).
 * <p>
 * {@code CF-Connecting-IP} wins when it holds a valid IP literal ({@code ipSource=cf-connecting-ip});
 * otherwise {@code request.getRemoteAddr()} is used ({@code ipSource=remote-addr}). Tomcat's
 * RemoteIpValve ({@code server.forward-headers-strategy: native}) may already have rewritten the
 * remote address from {@code X-Forwarded-For}, so both sources are header-derived and spoofable
 * in-cluster (docs/060 §10). Only literals are accepted — no value ever triggers a DNS lookup.
 */
public final class ClientIpResolver {

    public static final String CF_CONNECTING_IP = "CF-Connecting-IP";
    public static final String SOURCE_CF = "cf-connecting-ip";
    public static final String SOURCE_REMOTE = "remote-addr";

    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9A-Fa-f:.]{2,45}$");

    public record ResolvedIp(String ip, String source) {
    }

    private ClientIpResolver() {
    }

    public static ResolvedIp resolve(HttpServletRequest request) {
        String cf = normalize(request.getHeader(CF_CONNECTING_IP));
        if (cf != null) {
            return new ResolvedIp(cf, SOURCE_CF);
        }
        return new ResolvedIp(normalize(request.getRemoteAddr()), SOURCE_REMOTE);
    }

    /**
     * @return the canonical textual form of an IPv4/IPv6 literal, or {@code null} if the value is
     *         not a plain IP literal (hostnames, zone ids, ports and garbage are rejected)
     */
    static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (IPV4.matcher(v).matches()) {
            return v;
        }
        if (v.indexOf(':') >= 0 && IPV6_CHARS.matcher(v).matches()) {
            try {
                // A string containing ':' is parsed as an IPv6 literal; no name resolution happens.
                return InetAddress.getByName(v).getHostAddress();
            } catch (UnknownHostException | IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }
}
