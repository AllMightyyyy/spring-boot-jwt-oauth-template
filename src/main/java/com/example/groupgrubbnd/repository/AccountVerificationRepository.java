package com.example.groupgrubbnd.repository;

import com.example.groupgrubbnd.entity.AccountVerification;
import com.example.groupgrubbnd.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface AccountVerificationRepository extends JpaRepository<AccountVerification, Long> {
    AccountVerification findByUser(User user);
    AccountVerification findByToken(String token);
}
