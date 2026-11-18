package ch.furchert.homelab.auth.config;

import jakarta.servlet.DispatcherType;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.EnumSet;

/** Registers {@link NoIndexHeaderFilter} ahead of every security chain, for all dispatcher types. */
@Configuration
public class NoIndexHeaderConfig {

    @Bean
    FilterRegistrationBean<NoIndexHeaderFilter> noIndexHeaderFilterRegistration() {
        FilterRegistrationBean<NoIndexHeaderFilter> reg = new FilterRegistrationBean<>(new NoIndexHeaderFilter());
        reg.setName("noIndexHeaderFilter");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        reg.addUrlPatterns("/*");
        reg.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
        return reg;
    }
}
