package org.course_planner.authentication.dto.password_hash;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordHashRequest {
    private String plainTextPassword;
}
