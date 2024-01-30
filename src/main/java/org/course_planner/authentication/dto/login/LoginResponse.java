package org.course_planner.authentication.dto.login;

public record LoginResponse(String token, String refreshToken, String username, String userId, Long expiresAt) {
}
