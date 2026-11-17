package org.example.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        MediaTypeServerWebExchangeMatcher browserMatcher = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
        browserMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

        RedirectServerAuthenticationEntryPoint redirectEntryPoint =
                new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/keycloak");

        DelegatingServerAuthenticationEntryPoint entryPoint = new DelegatingServerAuthenticationEntryPoint(
                List.of(new DelegatingServerAuthenticationEntryPoint.DelegateEntry(browserMatcher, redirectEntryPoint))
        );
        entryPoint.setDefaultEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/oauth2/**", "/login/**", "/error").permitAll()
                        .anyExchange().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint))
                .oauth2Login(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }
}
