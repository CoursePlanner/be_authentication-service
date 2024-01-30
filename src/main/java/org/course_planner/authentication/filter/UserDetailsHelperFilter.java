package org.course_planner.authentication.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.course_planner.authentication.dto.login.LoginRequest;
import org.course_planner.authentication.service.impl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class UserDetailsHelperFilter extends OncePerRequestFilter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        CachedBodyHttpServletRequest cachedBodyHttpServletRequest = new CachedBodyHttpServletRequest(request);
        byte[] body = StreamUtils.copyToByteArray(cachedBodyHttpServletRequest.getInputStream());
        LoginRequest loginRequest = getRequestBody(body, LoginRequest.class);
        if (loginRequest != null && loginRequest.getUserProfileDTO() != null) {
            userDetailsService.addUserToMap(loginRequest.getUserProfileDTO());
        }
        filterChain.doFilter(cachedBodyHttpServletRequest, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getRequestURI().endsWith("/login");
    }

    private  <T> T getRequestBody(byte[] cachedBody, Class<T> returnType) {
        try {
            ObjectMapper mapper = getObjectMapper();
            return mapper.readValue(cachedBody, returnType);
        } catch (Exception ex) {
            return null;
        }
    }

    private ObjectMapper getObjectMapper() {
        return JsonMapper.builder().addModule(new JavaTimeModule()).build();
    }
}
