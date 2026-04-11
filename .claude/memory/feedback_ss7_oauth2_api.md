---
name: Spring Security 7 OAuth2 Authorization Server API
description: In SS 7.0.4 (bundled with SB 4.0.5), use http.oauth2AuthorizationServer() not OAuth2AuthorizationServerConfigurer.authorizationServer()
type: feedback
---

In Spring Security 7.0.4 (Spring Boot 4.0.5), the static method `OAuth2AuthorizationServerConfigurer.authorizationServer()` does NOT exist. Use the HttpSecurity DSL method instead:

```java
http.oauth2AuthorizationServer(as -> as
    .oidc(oidc -> oidc
        .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(mapper))
        .providerConfigurationEndpoint(Customizer.withDefaults())
        .logoutEndpoint(Customizer.withDefaults())
    )
);
```

**Why:** The old pattern (`http.with(OAuth2AuthorizationServerConfigurer.authorizationServer(), ...)`) was from Spring AS 1.2-1.5. Spring Security 7 integrates the AS configurer directly into HttpSecurity.

**How to apply:** Whenever configuring Spring Authorization Server filter chains, use `http.oauth2AuthorizationServer(...)`. The sub-configurer API (`.oidc()`, `.userInfoEndpoint()`, etc.) remains the same. Also means a single filter chain can combine AS + resource server + form login.
