package org.course_planner.authentication.service.impl;

import org.course_planner.authentication.dto.login.UserProfileDTO;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final ConcurrentHashMap<String, UserProfileDTO> inMemoryUserDB = new ConcurrentHashMap<>();
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return inMemoryUserDB.getOrDefault(username, null);
    }

    public void addUserToMap(UserProfileDTO userProfileDTO) {
        inMemoryUserDB.put(userProfileDTO.getUsername(), userProfileDTO);
    }

    public void removeUserFromMap(String username) {
        inMemoryUserDB.remove(username);
    }
}
