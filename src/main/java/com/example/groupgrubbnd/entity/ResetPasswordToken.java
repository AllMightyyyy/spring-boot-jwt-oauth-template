package com.example.groupgrubbnd.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "reset_password_tokens")
@Data
public class ResetPasswordToken {
    @Id
    private String token;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private LocalDateTime expirationTime;
}
