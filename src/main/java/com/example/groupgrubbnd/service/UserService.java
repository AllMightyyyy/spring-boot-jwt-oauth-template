package com.example.groupgrubbnd.service;

import com.example.groupgrubbnd.config.JwtUtils;
import com.example.groupgrubbnd.entity.AccountVerification;
import com.example.groupgrubbnd.entity.ResetPasswordToken;
import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.LoginResponseDTO;
import com.example.groupgrubbnd.repository.AccountVerificationRepository;
import com.example.groupgrubbnd.repository.OauthTokenRepository;
import com.example.groupgrubbnd.repository.ResetPasswordTokenRepository;
import com.example.groupgrubbnd.repository.UserRepository;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

/**
 * Service responsible for managing users.
 */
@Slf4j
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AccountVerificationRepository accountVerificationRepository;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;
    private final EmailService emailService;
    private final TokenService tokenService;
    private final JwtUtils jwtUtils;
    private final OauthTokenRepository tokenRepository;

    @Value("${OAUTH2_GOOGLE_REDIRECT_URI}")
    private String googleRedirectURI;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Autowired
    public UserService(PasswordEncoder passwordEncoder,
                       UserRepository userRepository,
                       AccountVerificationRepository accountVerificationRepository,
                       ResetPasswordTokenRepository resetPasswordTokenRepository,
                       EmailService emailService,
                       TokenService tokenService,
                       JwtUtils jwtUtils,
                       OauthTokenRepository tokenRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.accountVerificationRepository = accountVerificationRepository;
        this.resetPasswordTokenRepository = resetPasswordTokenRepository;
        this.emailService = emailService;
        this.tokenService = tokenService;
        this.jwtUtils = jwtUtils;
        this.tokenRepository = tokenRepository;
    }

    /**
     * Authenticates a user and generates JWT tokens.
     *
     * @param email    User's email
     * @param password User's password
     * @return LoginResponseDTO containing tokens
     */
    public LoginResponseDTO login(String email, String password) {
        User user = userRepository.findByEmail(email);

        if (user != null && passwordEncoder.matches(password, user.getPassword()) && user.isEnabled()) {
            log.info("User authenticated successfully: {}", email);
            return generateTokenForUser(user);
        }

        log.warn("Failed login attempt for email: {}", email);
        throw new BadCredentialsException("Invalid username or password");
    }

    /**
     * Generates JWT token for the user.
     *
     * @param user Authenticated user
     * @return LoginResponseDTO containing JWT tokens
     */
    public LoginResponseDTO generateTokenForUser(User user) {
        String jwtToken = jwtUtils.generateJwtToken(user);

        LoginResponseDTO dto = new LoginResponseDTO();
        dto.setAccessToken(jwtToken);
        dto.setExpirationTime(LocalDateTime.now().plus(Duration.ofMillis(jwtExpirationMs)));

        // Optionally handle refresh tokens here if needed

        log.info("JWT token generated for user: {}", user.getEmail());
        return dto;
    }

    /**
     * Registers a new user and sends a verification email.
     *
     * @param firstName User's first name
     * @param lastName  User's last name
     * @param email     User's email
     * @param password  User's password
     * @return Registered user
     */
    public User registerUser(String firstName, String lastName, String email, String password) {
        User existingUser = userRepository.findByEmail(email);

        if (existingUser != null) {
            if (!existingUser.isEnabled()) {
                // Resend verification email for disabled users
                sendAccountVerificationMail(existingUser);
                return existingUser;
            }
            throw new IllegalStateException("User already exists and is enabled.");
        }

        User user = new User();
        user.setEnabled(false); // Disabled by default
        user.setEmailVerified(false);
        user.setRole("USER");
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));

        user = userRepository.save(user);

        sendAccountVerificationMail(user);
        return user;
    }

    /**
     * Logs out the user by deleting their OAuth tokens.
     *
     * @param email User's email
     * @return Status message
     */
    public String logout(String email) {
        User user = userRepository.findByEmail(email);
        if(user != null) {
            tokenRepository.deleteByUser(user);
            log.info("User logged out successfully: {}", email);
            return "Logged out successfully!";
        }
        log.warn("Logout attempted for non-existent user: {}", email);
        return "User not found";
    }

    /**
     * Sends an account verification email to the user with the provided token.
     *
     * @param user User to send the email to
     */
    public void sendAccountVerificationMail(User user) {
        AccountVerification verification = accountVerificationRepository.findByUser(user);

        if (verification == null) {
            verification = new AccountVerification();
            verification.setUser(user);
        }

        // Update the token
        verification.setToken(UUID.randomUUID().toString());

        // Save the updated or new verification token
        accountVerificationRepository.save(verification);

        // Send verification email via EmailService
        emailService.sendAccountVerificationEmail(user, verification.getToken());
    }

    /**
     * Verifies a user's account using the verification token.
     *
     * @param token Verification token
     * @return Verification message
     */
    public String verifyAccount(String token) {
        // Find the verification record by token
        AccountVerification verification = accountVerificationRepository.findByToken(token);

        if (verification == null) {
            return "Invalid verification token"; // Token not found
        }

        // Mark the user as verified and enabled
        User user = verification.getUser();
        if (user != null) {
            user.setEnabled(true);
            user.setEmailVerified(true);
            userRepository.save(user);

            // Delete the used verification token
            accountVerificationRepository.delete(verification);

            return "Account verified successfully!";
        }

        return "User not found";
    }

    /**
     * Registers a new OAuth2 user.
     *
     * @param googleUser User details from Google
     * @return Registered user
     */
    public User registerOAuth2User(User googleUser) {
        User user = new User();
        user.setFirstName(googleUser.getFirstName());
        user.setLastName(googleUser.getLastName());
        user.setEmail(googleUser.getEmail());
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString())); // Random password
        user.setRole("USER");
        user.setEnabled(true); // Enabled by default for OAuth2
        user.setEmailVerified(true);

        return userRepository.save(user);
    }

    /**
     * Processes the OAuth2 grant code to authenticate or register a user.
     *
     * @param code OAuth2 authorization code
     * @return LoginResponseDTO containing tokens
     */
    public LoginResponseDTO processGrantCode(String code) {
        String accessToken = getOauthAccessTokenGoogle(code);
        User googleUser = getProfileDetailsGoogle(accessToken);
        User user = userRepository.findByEmail(googleUser.getEmail());

        if(user == null) {
            user = registerOAuth2User(googleUser);
        } else {
            user.setEnabled(true); // Enable existing user
            user.setEmailVerified(true);
            userRepository.save(user);
        }

        return tokenService.generateAndSaveTokens(user);
    }

    /**
     * Retrieves user profile details from Google using the access token.
     *
     * @param accessToken OAuth2 access token
     * @return User object with Google profile details
     */
    private User getProfileDetailsGoogle(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "https://www.googleapis.com/oauth2/v2/userinfo";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        JsonObject jsonObject = new Gson().fromJson(response.getBody(), JsonObject.class);

        User user = new User();
        user.setEmail(jsonObject.get("email").getAsString());
        user.setFirstName(jsonObject.get("given_name").getAsString());
        user.setLastName(jsonObject.get("family_name").getAsString());
        user.setPassword(UUID.randomUUID().toString()); // Placeholder password
        return user;
    }

    /**
     * Exchanges the authorization code for an access token with Google.
     *
     * @param code OAuth2 authorization code
     * @return Access token
     */
    private String getOauthAccessTokenGoogle(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("redirect_uri", googleRedirectURI);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        String url = "https://oauth2.googleapis.com/token";
        ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
        JsonObject jsonObject = new Gson().fromJson(response.getBody(), JsonObject.class);

        return jsonObject.get("access_token").getAsString();
    }

    /**
     * Initiates a password reset by sending a reset link to the user's email.
     *
     * @param email User's email
     * @return Status message
     */
    public String initiateResetPasswordLink(String email) {
        User user = userRepository.findByEmail(email);
        if(user == null) {
            return "Email address not registered";
        }

        ResetPasswordToken resetToken = new ResetPasswordToken();
        resetToken.setToken(generateSecureToken());
        resetToken.setUser(user);
        resetToken.setExpirationTime(LocalDateTime.now().plusHours(1));
        resetPasswordTokenRepository.save(resetToken);

        // Send password reset email via EmailService
        emailService.sendPasswordResetEmail(user, resetToken.getToken());

        return "Password reset link sent to your email.";
    }

    /**
     * Changes the user's password using a reset token.
     *
     * @param token       Reset token
     * @param newPassword New password
     * @return Status message
     */
    public String changePasswordWithToken(String token, String newPassword) {
        ResetPasswordToken resetToken = resetPasswordTokenRepository.findById(token).orElse(null);
        if(resetToken == null || resetToken.getExpirationTime().isBefore(LocalDateTime.now())) {
            return "Invalid or expired token";
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        resetPasswordTokenRepository.delete(resetToken);

        return "Password changed successfully!";
    }

    /**
     * Sets the user's password and activates their account.
     *
     * @param token       Temporary token
     * @param newPassword New password
     * @return Status message
     */
    public String setPassword(String token, String newPassword) {
        String email = tokenService.getEmailByTempToken(token);

        if (email == null) {
            return "Invalid or expired token";
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            return "User not found";
        }

        // Update user record
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setEnabled(true); // Activate the user
        user.setEmailVerified(true); // Mark as verified
        userRepository.save(user);

        // Remove the temporary token
        tokenService.removeTempToken(token);

        return "Password set successfully!";
    }

    /**
     * Generates a secure token using Base64 encoding.
     *
     * @return Secure token string
     */
    private String generateSecureToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[24];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Retrieves a user by their email.
     *
     * @param email User's email
     * @return User object or null if not found
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
