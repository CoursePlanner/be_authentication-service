package org.course_planner.authentication.service;

import org.course_planner.authentication.dto.login.LoginRequest;
import org.course_planner.authentication.dto.login.LoginResponse;
import org.springframework.security.core.Authentication;

public interface AuthenticationService {
    LoginResponse generateToken(LoginRequest request, Authentication authentication);
}
