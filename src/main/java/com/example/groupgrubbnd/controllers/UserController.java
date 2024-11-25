package com.example.groupgrubbnd.controllers;

import com.example.groupgrubbnd.model.UserDTO;
import com.example.groupgrubbnd.repository.UserRepository;
import com.example.groupgrubbnd.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "Endpoints for user management")
public class UserController {
    private final UserRepository userRepository;

    @Autowired
    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Operation(summary = "Get user details", description = "Retrieves user details by ID. Users can only access their own data.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User details retrieved successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "403", description = "Forbidden - Accessing other user's data"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUser(
            @Parameter(description = "User ID", required = true)
            @PathVariable Long id,
            @AuthenticationPrincipal User authenticatedUser) {

        if (!id.equals(authenticatedUser.getId())) {
            throw new AccessDeniedException("Access denied: You can only view your own data.");
        }

        User foundUser = userRepository.findById(id).orElse(null);
        if (foundUser == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(UserDTO.from(foundUser));
    }
}
