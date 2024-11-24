package com.example.groupgrubbnd.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Collection;
import java.util.List;
import java.util.ArrayList;

@Entity
@Table(name = "users")
@Data
@Schema(description = "Entity representing a user in the system")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Schema(description = "Unique identifier for the user", example = "1")
    private Long id;

    @Schema(description = "User's first name", example = "John")
    private String firstName;

    @Schema(description = "User's last name", example = "Doe")
    private String lastName;

    @Column(unique = true)
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @Schema(description = "User's password (hashed)", example = "$2a$10$...")
    private String password;

    @Schema(description = "User's role", example = "USER")
    private String role;

    @Schema(description = "Indicates if the user account is enabled", example = "true")
    private boolean enabled;

    @Schema(description = "Indicates if the user's email is verified", example = "true")
    private boolean emailVerified;

    // Relationships
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @Schema(description = "Account verification details associated with the user")
    private AccountVerification accountVerification;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @Schema(description = "List of reset password tokens associated with the user")
    private List<ResetPasswordToken> resetPasswordTokens = new ArrayList<>();

    // UserDetails interface methods

    @Override
    @Schema(hidden = true)
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority(role));
        return authorities;
    }

    @Override
    @Schema(description = "User's email address as username", example = "john.doe@example.com")
    public String getUsername() {
        return email;
    }

    // Other UserDetails methods

    @Override
    @Schema(hidden = true)
    public boolean isAccountNonExpired() {
        return enabled;
    }

    @Override
    @Schema(hidden = true)
    public boolean isAccountNonLocked() {
        return enabled;
    }

    @Override
    @Schema(hidden = true)
    public boolean isCredentialsNonExpired() {
        return enabled;
    }

    @Override
    @Schema(hidden = true)
    public boolean isEnabled() {
        return enabled;
    }
}
