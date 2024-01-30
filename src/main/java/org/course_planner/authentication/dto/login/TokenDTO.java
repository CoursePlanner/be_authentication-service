package org.course_planner.authentication.dto.login;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenDTO {
    private String token;
    private Long expiresAt;
    private Long issuedAt;
}