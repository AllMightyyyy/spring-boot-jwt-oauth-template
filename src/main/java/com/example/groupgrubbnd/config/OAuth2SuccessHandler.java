package com.example.groupgrubbnd.config;

import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.LoginResponseDTO;
import com.example.groupgrubbnd.repository.UserRepository;
import com.example.groupgrubbnd.service.TokenService;
import com.example.groupgrubbnd.service.UserService;
import jakarta.servlet.http.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Value("${APP_REGISTRATION_URL}")
    private String appRegistrationUrl;

    @Autowired
    public OAuth2SuccessHandler(TokenService tokenService, UserRepository userRepository, UserService userService) {
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        if (email == null) {
            response.sendRedirect("/login?error=email-not-found");
            return;
        }

        User user = userRepository.findByEmail(email);

        if (user == null) {
            // Redirect to a page to complete registration
            String tempToken = UUID.randomUUID().toString();
            tokenService.storeTempToken(tempToken, email);
            response.sendRedirect(appRegistrationUrl + "?token=" + tempToken);
            return;
        }

        // If user exists, generate tokens and redirect
        LoginResponseDTO dto = tokenService.generateTokenForUser(user);
        String redirectUrl = appRegistrationUrl + "?accessToken=" + dto.getAccessToken();
        response.sendRedirect(redirectUrl);
    }
}