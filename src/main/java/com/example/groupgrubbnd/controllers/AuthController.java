package com.example.groupgrubbnd.controllers;

import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.*;
import com.example.groupgrubbnd.helper.LoginHelper;
import com.example.groupgrubbnd.repository.UserRepository;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.responses.*;
import io.swagger.v3.oas.annotations.media.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints for user authentication and authorization")
public class AuthController {
    private final LoginHelper loginHelper;
    private final UserRepository userRepository;

    @Value("${FRONTEND_IP}")
    private String frontEndUrl;

    public AuthController(LoginHelper loginHelper, UserRepository userRepository) {
        this.loginHelper = loginHelper;
        this.userRepository = userRepository;
    }

    @Operation(summary = "Register a new user", description = "Registers a new user and sends a verification email.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/register")
    @Transactional
    public ResponseEntity<String> register(@Valid @RequestBody SignUpDTO signUpDTO) {
        try {
            User existingUser = userRepository.findByEmail(signUpDTO.getEmail());

            if (existingUser != null) {
                if (!existingUser.isEnabled()) {
                    // Resend verification email for disabled users
                    loginHelper.sendAccountVerificationMail(existingUser);
                    return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                            "User already registered but not enabled. A new verification email has been sent.");
                } else {
                    // User is already enabled
                    return ResponseEntity.ok("User already exists and is enabled.");
                }
            }

            // New user registration
            loginHelper.registerUser(
                    signUpDTO.getFirstName(),
                    signUpDTO.getLastName(),
                    signUpDTO.getEmail(),
                    signUpDTO.getPassword()
            );
            return ResponseEntity.status(HttpStatus.CREATED).body(
                    "User registered successfully! Please check your email to verify your account.");
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
        }
    }

    @Operation(summary = "User login", description = "Authenticates a user and returns JWT tokens.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDTO.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials")
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(
            @Parameter(description = "User's email", required = true)
            @RequestParam String email,
            @Parameter(description = "User's password", required = true)
            @RequestParam String password) {
        try {
            LoginResponseDTO dto = loginHelper.login(email, password);
            return ResponseEntity.ok(dto);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @Operation(summary = "Refresh access token", description = "Generates a new access token using a refresh token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDTO.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or expired refresh token")
    })
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDTO> refreshAccessToken(
            @Parameter(description = "Refresh token", required = true)
            @RequestParam String refreshToken) {
        try {
            LoginResponseDTO dto = loginHelper.refreshAccessToken(refreshToken);
            return ResponseEntity.ok(dto);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @Operation(summary = "User logout", description = "Logs out the user by invalidating their tokens.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logged out successfully"),
            @ApiResponse(responseCode = "400", description = "User not authenticated"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth != null && auth.isAuthenticated()) {
            String email = auth.getName();
            String message = loginHelper.logout(email);
            return ResponseEntity.ok(message);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User not authenticated");
    }

    @Operation(summary = "Verify user account", description = "Verifies a user's account using a token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirects to profile on success"),
            @ApiResponse(responseCode = "302", description = "Redirects to error page on failure")
    })
    @GetMapping("/verify")
    public void verifyAccount(
            @Parameter(description = "Verification token", required = true)
            @RequestParam String token,
            HttpServletResponse response) {
        String message = loginHelper.verifyAccount(token);
        try {
            if ("Account verified successfully!".equals(message)) {
                response.sendRedirect(frontEndUrl + "profile");
            } else {
                response.sendRedirect(frontEndUrl + "error?message=" + URLEncoder.encode(message, StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new RuntimeException("Error while redirecting", e);
        }
    }

    @Operation(summary = "Set user password", description = "Sets a new password for a user using a token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password set successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token / User not found")
    })
    @PostMapping("/set-password")
    public ResponseEntity<String> setPassword(
            @Valid @RequestBody SetPasswordRequest request) {
        String message = loginHelper.setPassword(request.getToken(), request.getNewPassword());
        if ("Password set successfully!".equals(message)) {
            return ResponseEntity.ok(message);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
        }
    }

    @Operation(summary = "Initiate password reset", description = "Sends a password reset link to the user's email.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset link sent"),
            @ApiResponse(responseCode = "404", description = "Email address not registered")
    })
    @PostMapping("/reset-password/request")
    public ResponseEntity<String> initiateResetPassword(
            @Parameter(description = "User's email", required = true)
            @RequestParam String email) {
        String message = loginHelper.initiateResetPasswordLink(email);
        if ("Password reset link sent to your email.".equals(message)) {
            return ResponseEntity.ok(message);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(message);
        }
    }

    @Operation(summary = "Confirm password reset", description = "Changes the user's password using a reset token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    })
    @PostMapping("/reset-password/confirm")
    public ResponseEntity<String> changePassword(
            @Parameter(description = "Reset token", required = true)
            @RequestParam String token,
            @Parameter(description = "New password", required = true)
            @RequestParam String newPassword) {
        String message = loginHelper.changePasswordWithToken(token, newPassword);
        if ("Password changed successfully!".equals(message)) {
            return ResponseEntity.ok(message);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
        }
    }

    @Operation(summary = "Resend verification email", description = "Resends the account verification email to the user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification email resent successfully"),
            @ApiResponse(responseCode = "400", description = "User is already enabled"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PostMapping("/resend-verification-email")
    public ResponseEntity<String> resendVerificationEmail(
            @Parameter(description = "User's email", required = true)
            @RequestParam String email) {
        User user = userRepository.findByEmail(email);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        }

        if (user.isEnabled()) {
            return ResponseEntity.badRequest().body("User is already enabled.");
        }

        loginHelper.sendAccountVerificationMail(user);
        return ResponseEntity.ok("Verification email resent successfully.");
    }
}
