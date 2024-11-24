package com.example.groupgrubbnd.model;

import com.example.groupgrubbnd.entity.User;
import lombok.Builder;
import lombok.Data;
import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Builder
@Schema(description = "Data transfer object for user details")
public class UserDTO {
    @Schema(description = "User ID", example = "1")
    private Long id;

    @Schema(description = "User's first name", example = "John")
    private String firstName;

    @Schema(description = "User's last name", example = "Doe")
    private String lastName;

    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @Schema(description = "User's role", example = "USER")
    private String role;

    public static UserDTO from(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}
