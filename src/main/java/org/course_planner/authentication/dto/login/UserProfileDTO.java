package org.course_planner.authentication.dto.login;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDTO implements UserDetails {
    private String userId;
    private String fullName;
    private String emailId;
    private String username;
    private String password;
    private boolean enabled;
    private List<String> authorities;
    private LocalDateTime createdOn;
    private LocalDateTime updatedOn;

    public List<SimpleGrantedAuthority> getAuthorities() {
        return authorities.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
