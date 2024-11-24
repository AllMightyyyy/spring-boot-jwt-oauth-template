package com.example.groupgrubbnd.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "account_verifications", uniqueConstraints = {
        @UniqueConstraint(columnNames = "user_id")
})
@Data
public class AccountVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // Auto-generated primary key

    @OneToOne
    @JoinColumn(name = "user_id", unique = true)
    private User user;

    @Column(unique = true)
    private String token; // Verification token
}

