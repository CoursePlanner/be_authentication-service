package org.course_planner.authentication.config;

import org.course_planner.authentication.filter.UserDetailsHelperFilter;
import org.course_planner.authentication.service.impl.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Order(1)
public class BasicWebSecurityConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(BasicWebSecurityConfig.class);

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserDetailsHelperFilter userDetailsHelperFilter;

    @Bean
    public SecurityFilterChain basicSecurityFilterChain(HttpSecurity security) throws Exception {
        security.csrf(AbstractHttpConfigurer::disable);
        security.formLogin(AbstractHttpConfigurer::disable);
        security.securityMatcher("/login").authorizeHttpRequests(request -> {
            request.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
            request.requestMatchers(HttpMethod.POST, "/login").authenticated();
        });
        security.userDetailsService(userDetailsService);
        security.headers(headerConfig -> {
            headerConfig.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });
        security.addFilterBefore(userDetailsHelperFilter, BasicAuthenticationFilter.class);
        security.httpBasic(Customizer.withDefaults());
        return security.build();
    }
}
