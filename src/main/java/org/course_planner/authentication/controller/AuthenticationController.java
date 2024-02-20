package org.course_planner.authentication.controller;

import org.course_planner.authentication.dto.login.LoginRequest;
import org.course_planner.authentication.dto.login.LoginResponse;
import org.course_planner.authentication.dto.validate_token.TokenValidationResponse;
import org.course_planner.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthenticationController {
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping(value = "/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request, Authentication authentication) {
        return new ResponseEntity<>(authenticationService.generateToken(request, authentication), HttpStatus.OK);
    }
    @GetMapping(value = "/validate")
    public ResponseEntity<TokenValidationResponse> validate(Authentication authentication) {
        return new ResponseEntity<>(new TokenValidationResponse(authentication), HttpStatus.OK);
    }
}
