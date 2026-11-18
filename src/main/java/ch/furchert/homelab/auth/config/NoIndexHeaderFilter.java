package ch.furchert.homelab.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Keeps the IdP out of search indexes (#168): every response, from any security chain, redirects,
 * error dispatches and unmatched paths included, carries {@code X-Robots-Tag: noindex, nofollow}.
 * Done as a plain servlet filter instead of per-chain header writers so no chain can miss it.
 * robots.txt is deliberately not used: crawlers must be able to fetch a page to see the header.
 */
@Configuration
public class NoIndexHeaderFilter extends OncePerRequestFilter {

    static final String HEADER = "X-Robots-Tag";
    static final String VALUE = "noindex, nofollow";

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader(HEADER, VALUE);
        chain.doFilter(request, response);
    }

    @Bean
    FilterRegistrationBean<NoIndexHeaderFilter> noIndexHeaderFilterRegistration() {
        FilterRegistrationBean<NoIndexHeaderFilter> reg = new FilterRegistrationBean<>(new NoIndexHeaderFilter());
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        reg.addUrlPatterns("/*");
        return reg;
    }
}
