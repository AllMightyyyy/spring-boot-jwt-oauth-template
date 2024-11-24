package com.example.groupgrubbnd.service;

import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class OAuth2UserServiceImpl implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            // Register new OAuth2 user
            user = new User();
            user.setFirstName(oAuth2User.getAttribute("given_name"));
            user.setLastName(oAuth2User.getAttribute("family_name"));
            user.setEmail(email);
            user.setPassword(""); // Empty password for OAuth2 users
            user.setRole("USER");
            user.setEnabled(true);
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Registered new OAuth2 user: {}", email);
        } else if (!user.isEnabled()) {
            user.setEnabled(true);
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Enabled existing OAuth2 user: {}", email);
        }

        return oAuth2User;
    }
}
