package com.example.groupgrubbnd.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "oauth_tokens")
@Data
public class OauthToken {
    @Id
    private String accessToken;

    @Column(unique = true)
    private String refreshToken;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private LocalDateTime expirationTime;
}
