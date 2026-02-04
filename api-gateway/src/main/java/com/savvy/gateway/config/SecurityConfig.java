package com.savvy.gateway.config;

import com.savvy.gateway.exception.GatewayExceptionHandler;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableConfigurationProperties({SecurityProperties.class, JwtProps.class})
public class SecurityConfig {

    private static final String SUPER_PERMISSION = "SYSTEM_ADMIN";

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            SecurityProperties props,
            GatewayExceptionHandler handlers,
            ReactiveJwtDecoder jwtDecoder,
            Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter
    ) {
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                        .jwtDecoder(jwtDecoder)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter)
                )
                .authenticationEntryPoint(handlers.authenticationEntryPoint())
        );

        http.exceptionHandling(e -> e
                .authenticationEntryPoint(handlers.authenticationEntryPoint())
                .accessDeniedHandler(handlers.accessDeniedHandler())
        );

        http.authorizeExchange(exchanges -> {
            exchanges.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();

            for (String p : props.getPublicPaths()) {
                exchanges.pathMatchers(p).permitAll();
            }

            for (SecurityProperties.PermissionRule rule : props.getPermissionsMapping()) {
                List<String> required = mergeWithSystemAdmin(rule.getRequire());

                for (String path : rule.getPaths()) {
                    if (rule.getMethods() == null || rule.getMethods().isEmpty()) {
                        exchanges.pathMatchers(path).hasAnyAuthority(required.toArray(String[]::new));
                    } else {
                        for (String m : rule.getMethods()) {
                            HttpMethod method = HttpMethod.valueOf(m);
                            exchanges.pathMatchers(method, path).hasAnyAuthority(required.toArray(String[]::new));
                        }
                    }
                }
            }

            exchanges.anyExchange().authenticated();
        });

        return http.build();
    }

    private List<String> mergeWithSystemAdmin(List<String> requires) {
        List<String> out = new ArrayList<>();
        out.add(SUPER_PERMISSION);
        if (requires != null) out.addAll(requires);
        return out;
    }
}
