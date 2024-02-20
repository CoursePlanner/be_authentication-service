package org.course_planner.authentication.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.NonNull;
import org.course_planner.authentication.service.RSAKeyPairProviderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtWebSecurityConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtWebSecurityConfig.class);

    private static final String[] allowedHeaders = {"x-user-id", "x-auth-code"};

    @Autowired
    @Qualifier("StaticRSAKeyPairProviderServiceImpl")
    private RSAKeyPairProviderService rsaKeyPairProviderService;

    @Bean
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity security) throws Exception {
        security.csrf(AbstractHttpConfigurer::disable);
        security.formLogin(AbstractHttpConfigurer::disable);
        security.httpBasic(AbstractHttpConfigurer::disable);
        security.sessionManagement(session -> {
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });
        security.authorizeHttpRequests(request -> {
            request.requestMatchers(HttpMethod.POST, "/login").permitAll();
            request.anyRequest().authenticated();
        });
        security.oauth2ResourceServer(resourceServerConfig -> {
            resourceServerConfig.jwt(jwtConfigurer -> {
                jwtConfigurer.decoder(jwtDecoder());
            });
        });

        return security.build();
    }

    @Bean
    public WebMvcConfigurer webMvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@NonNull CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedHeaders(allowedHeaders);
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            return NimbusJwtDecoder.withPublicKey(rsaKeyPairProviderService
                    .rsaKey().toRSAPublicKey()).build();
        } catch (Exception ex) {
            throw new RuntimeException("jwtDecoder: Failed to construct RSA key: ", ex);
        }
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(jwkSource());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            JWKSet jwkSet = new JWKSet(rsaKeyPairProviderService.rsaKey());
            return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
        } catch (Exception ex) {
            throw new RuntimeException("jwkSource: Failed to construct RSA key: ", ex);
        }
    }
}
