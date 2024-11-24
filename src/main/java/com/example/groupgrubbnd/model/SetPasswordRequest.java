package com.example.groupgrubbnd.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "Data transfer object for setting a new password")
public class SetPasswordRequest {
    @NotBlank(message = "Token is mandatory")
    @Schema(description = "Temporary token for password setting", example = "95ceec70-e63e-4f00-a96c-8604134cb291", required = true)
    private String token;

    @NotBlank(message = "New password is mandatory")
    @Schema(description = "New password to set", example = "NewStrongPassword123!", required = true)
    private String newPassword;
}
