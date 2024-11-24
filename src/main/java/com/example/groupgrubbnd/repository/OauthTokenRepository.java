package com.example.groupgrubbnd.repository;

import com.example.groupgrubbnd.entity.OauthToken;
import com.example.groupgrubbnd.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OauthTokenRepository extends JpaRepository<OauthToken, String> {
    OauthToken findByRefreshToken(String refreshToken);
    void deleteByUser(User user);
}
