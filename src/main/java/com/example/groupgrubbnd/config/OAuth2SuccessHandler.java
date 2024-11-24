package com.example.groupgrubbnd.config;

import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.LoginResponseDTO;
import com.example.groupgrubbnd.repository.UserRepository;
import com.example.groupgrubbnd.service.OAuth2UserServiceImpl;
import com.example.groupgrubbnd.helper.LoginHelper;
import jakarta.servlet.ServletException;
import static com.example.groupgrubbnd.config.AppConstants.*;
import jakarta.servlet.http.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final LoginHelper loginHelper;
    private final UserRepository userRepository;

    @Autowired
    public OAuth2SuccessHandler(LoginHelper loginHelper, UserRepository userRepository) {
        this.loginHelper = loginHelper;
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
            loginHelper.storeTempToken(tempToken, email);
            response.sendRedirect("http://localhost:3000/complete-registration?token=" + tempToken);
            return;
        }

        // If user exists, generate tokens and redirect
        LoginResponseDTO dto = loginHelper.generateTokenForUser(user);
        String redirectUrl = LOCALHOST_3000_PROFILE + "?accessToken=" + dto.getAccessToken();
        response.sendRedirect(redirectUrl);
    }
}