package com.example.groupgrubbnd.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "Data transfer object for user registration")
public class SignUpDTO {
    @NotBlank(message = "First name is mandatory")
    @Schema(description = "User's first name", example = "John")
    private String firstName;

    @NotBlank(message = "Last name is mandatory")
    @Schema(description = "User's last name", example = "Doe")
    private String lastName;

    @Email(message = "Email should be valid")
    @NotBlank(message = "Email is mandatory")
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @NotBlank(message = "Password is mandatory")
    @Schema(description = "User's password", example = "StrongPassword123!")
    private String password;
}
