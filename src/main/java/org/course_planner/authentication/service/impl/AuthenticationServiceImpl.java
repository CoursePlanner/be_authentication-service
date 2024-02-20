package org.course_planner.authentication.service.impl;

import org.course_planner.authentication.dto.login.LoginRequest;
import org.course_planner.authentication.dto.login.LoginResponse;
import org.course_planner.authentication.dto.login.TokenDTO;
import org.course_planner.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final String CONST_JWT_TOKEN_ISSUER_PROPERTY = "org.course_planner.authentication-service.jwt-configs.token-issuer";
    private static final String CONST_JWT_EXPIRY_IN_SECONDS_PROPERTY = "org.course_planner.authentication-service.jwt-configs.token-expiry-in-seconds";
    private static final String CONST_RJWT_EXPIRY_IN_SECONDS_PROPERTY = "org.course_planner.authentication-service.jwt-configs.refresh-token-expiry-in-seconds";

    @Autowired
    private Environment environment;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Override
    public LoginResponse generateToken(LoginRequest request, Authentication authentication) {
        TokenDTO token = getToken(authentication);
        TokenDTO refreshToken = getRefreshToken(authentication);
        return new LoginResponse(token.getToken(), refreshToken.getToken(), authentication.getName(),
                request.getUserProfileDTO().getUserId(), token.getExpiresAt());
    }

    private TokenDTO getToken(Authentication authentication) {
        Long expirySeconds = environment.getProperty(CONST_JWT_EXPIRY_IN_SECONDS_PROPERTY, Long.class, 3600L);
        String issuer = environment.getProperty(CONST_JWT_TOKEN_ISSUER_PROPERTY, String.class, "self");
        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setIssuedAt(Instant.now().toEpochMilli());
        tokenDTO.setExpiresAt(Instant.now().plusSeconds(expirySeconds).toEpochMilli());
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(Instant.ofEpochMilli(tokenDTO.getIssuedAt()))
                .expiresAt(Instant.ofEpochMilli(tokenDTO.getExpiresAt()))
                .subject(authentication.getName())
                .claim("scope", getScopes(authentication.getAuthorities()))
                .build();
        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwtClaimsSet);
        tokenDTO.setToken(jwtEncoder.encode(parameters).getTokenValue());
        return tokenDTO;
    }

    private TokenDTO getRefreshToken(Authentication authentication) {
        Long expirySeconds = environment.getProperty(CONST_RJWT_EXPIRY_IN_SECONDS_PROPERTY, Long.class, 7200L);
        String issuer = environment.getProperty(CONST_JWT_TOKEN_ISSUER_PROPERTY, String.class, "self");
        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setIssuedAt(Instant.now().toEpochMilli());
        tokenDTO.setExpiresAt(Instant.now().plusSeconds(expirySeconds).toEpochMilli());
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(Instant.ofEpochMilli(tokenDTO.getIssuedAt()))
                .expiresAt(Instant.ofEpochMilli(tokenDTO.getExpiresAt()))
                .subject(authentication.getName())
                .claim("scope", getScopes(authentication.getAuthorities()))
                .build();
        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwtClaimsSet);
        tokenDTO.setToken(jwtEncoder.encode(parameters).getTokenValue());
        return tokenDTO;
    }

    private List<String> getScopes(Collection<? extends GrantedAuthority> authorities) {
        if (authorities != null) {
            return authorities.stream().map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
        }
        return new LinkedList<>();
    }
}
