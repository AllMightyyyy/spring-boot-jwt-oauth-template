package com.example.groupgrubbnd.model;

import lombok.Data;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

@Data
@Schema(description = "Data transfer object for login responses")
public class LoginResponseDTO {
    @Schema(description = "JWT access token", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "Refresh token", example = "dGhpc0lzQWZhc3RDb250ZW50VG9rZW4=")
    private String refreshToken;

    @Schema(description = "Access token expiration time", example = "2024-12-31T23:59:59")
    private LocalDateTime expirationTime;
}
