package com.savvy.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.util.*;

@Configuration
public class JwtAuthConverterConfig {

    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        return new JwtToAuthTokenConverter();
    }

    static final class JwtToAuthTokenConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

        @Override
        public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
            return Mono.just(new JwtAuthenticationToken(jwt, authoritiesFromClaims(jwt)));
        }

        private Collection<GrantedAuthority> authoritiesFromClaims(Jwt jwt) {
            Set<GrantedAuthority> out = new LinkedHashSet<>();

            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                for (String r : roles) {
                    if (r == null || r.isBlank()) continue;
                    String name = r.trim().toUpperCase(Locale.ROOT);
                    out.add(new SimpleGrantedAuthority(name.startsWith("ROLE_") ? name : "ROLE_" + name));
                }
            }

            List<String> perms = jwt.getClaimAsStringList("permissions");
            if (perms != null) {
                for (String p : perms) {
                    if (p == null || p.isBlank()) continue;
                    out.add(new SimpleGrantedAuthority(p.trim().toUpperCase(Locale.ROOT)));
                }
            }

            return out;
        }
    }
}
