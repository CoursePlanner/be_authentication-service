package org.course_planner.authentication.dto.validate_token;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    private String principal;
    private List<String> authorities;
    private Long expiresAt;
    private Long issuedAt;
    private String issuer;

    public TokenValidationResponse(Authentication authentication) {
        this.principal = authentication.getName();
        this.authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .map(authority -> authority.replace("SCOPE_", "")).collect(Collectors.toList());
        Jwt jwt = (Jwt) authentication.getCredentials();
        this.expiresAt = jwt.getExpiresAt().toEpochMilli();
        this.issuedAt = jwt.getIssuedAt().toEpochMilli();
        this.issuer = jwt.getClaims().get("iss").toString();
    }
}
