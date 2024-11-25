package com.example.groupgrubbnd.helper;

import com.example.groupgrubbnd.config.JwtUtils;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.example.groupgrubbnd.entity.AccountVerification;
import com.example.groupgrubbnd.entity.OauthToken;
import com.example.groupgrubbnd.entity.ResetPasswordToken;
import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.EmailDetails;
import com.example.groupgrubbnd.model.LoginResponseDTO;
import com.example.groupgrubbnd.repository.AccountVerificationRepository;
import com.example.groupgrubbnd.repository.OauthTokenRepository;
import com.example.groupgrubbnd.repository.ResetPasswordTokenRepository;
import com.example.groupgrubbnd.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@Transactional
public class LoginHelper {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final OauthTokenRepository tokenRepository;
    private final AccountVerificationRepository accountVerificationRepository;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;
    private final EmailSender emailSender;
    private final Environment environment;
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtils jwtUtils;

    @Value("${OAUTH2_GOOGLE_REDIRECT_URI}")
    private String googleRedirectURI;

    @Value("${SERVER.ADDRESS}")
    private String serverAddress;

    @Value("${SERVER.PORT}")
    private String serverPort;

    @Autowired
    public LoginHelper(PasswordEncoder passwordEncoder,
                       UserRepository userRepository,
                       OauthTokenRepository tokenRepository,
                       AccountVerificationRepository accountVerificationRepository,
                       ResetPasswordTokenRepository resetPasswordTokenRepository,
                       EmailSender emailSender,
                       Environment environment,
                       RedisTemplate<String, String> redisTemplate,
                       JwtUtils jwtUtils) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.accountVerificationRepository = accountVerificationRepository;
        this.resetPasswordTokenRepository = resetPasswordTokenRepository;
        this.emailSender = emailSender;
        this.environment = environment;
        this.redisTemplate = redisTemplate;
        this.jwtUtils = jwtUtils;
    }

    private static final String TEMP_TOKEN_PREFIX = "temp_token:";

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

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
                sendAccountVerificationMail(existingUser);
                log.info("Resent verification email to existing user: {}", email);
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
        log.info("Registered new user: {}", email);
        return user;
    }

    /**
     * Sends an account verification email to the user.
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

        log.info("Generated and saved new verification token: {}", verification.getToken());

        // Send verification email with the new token
        String link = String.format("http://%s:%s/api/auth/verify?token=%s",
                environment.getProperty("server.address", serverAddress),
                environment.getProperty("server.port", serverPort),
                verification.getToken());

        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setRecipient(user.getEmail());
        emailDetails.setSubject("Account Verification");
        String body = "Thank you for registering. Please verify your account by clicking the link below:\n" + link;
        emailDetails.setBody(body);

        emailSender.sendSimpleMail(emailDetails);
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
     * Generates JWT tokens for a user and saves the OAuth token.
     *
     * @param user Authenticated user
     * @return LoginResponseDTO containing tokens
     */
    LoginResponseDTO saveTokenForUser(User user) {
        LoginResponseDTO dto = generateToken();
        OauthToken token = new OauthToken();
        token.setAccessToken(dto.getAccessToken());
        token.setRefreshToken(dto.getRefreshToken());
        token.setExpirationTime(dto.getExpirationTime());
        token.setUser(user);

        tokenRepository.save(token);
        log.info("Generated and saved OAuth tokens for user: {}", user.getEmail());
        return dto;
    }

    /**
     * Generates random access and refresh tokens.
     *
     * @return LoginResponseDTO with tokens
     */
    private LoginResponseDTO generateToken() {
        LoginResponseDTO res = new LoginResponseDTO();
        res.setAccessToken(UUID.randomUUID().toString());
        res.setRefreshToken(UUID.randomUUID().toString());
        res.setExpirationTime(LocalDateTime.now().plusHours(1));
        return res;
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
            log.info("Registered new OAuth2 user: {}", googleUser.getEmail());
        } else {
            user.setEnabled(true); // Enable existing user
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Enabled existing user: {}", googleUser.getEmail());
        }

        return saveTokenForUser(user);
    }

    /**
     * Registers a new OAuth2 user.
     *
     * @param googleUser User details from Google
     * @return Registered user
     */
    User registerOAuth2User(User googleUser) {
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
     * Retrieves user profile details from Google using the access token.
     *
     * @param accessToken OAuth2 access token
     * @return User object with Google profile details
     */
    User getProfileDetailsGoogle(String accessToken) {
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
    String getOauthAccessTokenGoogle(String code) {
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
     * Verifies a user's account using the verification token.
     *
     * @param token Verification token
     * @return Verification message
     */
    public String verifyAccount(String token) {
        // Find the verification record by token
        AccountVerification verification = accountVerificationRepository.findByToken(token);
        log.info("Looking for verification token: {}", token);

        if (verification == null) {
            log.warn("Invalid verification token: {}", token);
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

            log.info("Account verified successfully for user: {}", user.getEmail());
            return "Account verified successfully!";
        }

        log.error("User not found for verification token: {}", token);
        return "User not found";
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
            log.warn("Password reset requested for non-existent email: {}", email);
            return "Email address not registered";
        }

        ResetPasswordToken resetToken = new ResetPasswordToken();
        resetToken.setToken(generateSecureToken());
        resetToken.setUser(user);
        resetToken.setExpirationTime(LocalDateTime.now().plusHours(1));
        resetPasswordTokenRepository.save(resetToken);

        String link = String.format("http://%s:%s/changepassword?token=%s",
                environment.getProperty("server.address", serverAddress),
                environment.getProperty("server.port", serverPort),
                resetToken.getToken());

        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setRecipient(user.getEmail());
        emailDetails.setSubject("Reset Password");
        emailDetails.setBody("Click the link to reset your password: " + link);

        emailSender.sendSimpleMail(emailDetails);
        log.info("Password reset link sent to: {}", email);
        return "Password reset link sent to your email.";
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
     * Changes the user's password using a reset token.
     *
     * @param token       Reset token
     * @param newPassword New password
     * @return Status message
     */
    public String changePasswordWithToken(String token, String newPassword) {
        ResetPasswordToken resetToken = resetPasswordTokenRepository.findById(token).orElse(null);
        if(resetToken == null || resetToken.getExpirationTime().isBefore(LocalDateTime.now())) {
            log.warn("Invalid or expired reset token: {}", token);
            return "Invalid or expired token";
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        resetPasswordTokenRepository.delete(resetToken);

        log.info("Password changed successfully for user: {}", user.getEmail());
        return "Password changed successfully!";
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
     * Refreshes the access token using a refresh token.
     *
     * @param refreshToken Refresh token
     * @return New LoginResponseDTO containing tokens
     */
    public LoginResponseDTO refreshAccessToken(String refreshToken) {
        OauthToken oauthToken = tokenRepository.findByRefreshToken(refreshToken);
        if(oauthToken == null || oauthToken.getExpirationTime().isBefore(LocalDateTime.now())) {
            log.warn("Invalid or expired refresh token: {}", refreshToken);
            throw new BadCredentialsException("Invalid or expired refresh token");
        }

        // Delete old tokens
        tokenRepository.delete(oauthToken);
        log.info("Old OAuth tokens deleted for user: {}", oauthToken.getUser().getEmail());

        // Generate new tokens
        return saveTokenForUser(oauthToken.getUser());
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
     * Stores a temporary token in Redis mapped to the user's email.
     * Also creates a partial user record if not exists.
     *
     * @param token Temporary token
     * @param email User's email
     */
    public void storeTempToken(String token, String email) {
        redisTemplate.opsForValue().set(TEMP_TOKEN_PREFIX + token, email, 15, TimeUnit.MINUTES);

        // Check if user exists in the database
        User user = userRepository.findByEmail(email);
        if (user == null) {
            // Save a "partial" user record
            user = new User();
            user.setEmail(email);
            user.setEnabled(false); // Mark as inactive
            user.setEmailVerified(false); // Mark as not verified
            user.setRole("USER");
            userRepository.save(user);
            log.info("Partial user record created for email: {}", email);
        }

        log.info("Temporary token stored: {} -> {}", token, email);
    }

    /**
     * Retrieves email associated with a temporary token from Redis.
     *
     * @param token Temporary token
     * @return User's email or null if not found
     */
    public String getEmailByTempToken(String token) {
        String email = redisTemplate.opsForValue().get(TEMP_TOKEN_PREFIX + token);
        log.debug("Lookup for token '{}': '{}'", token, email);
        return email;
    }

    /**
     * Removes a temporary token from Redis after use.
     *
     * @param token Temporary token
     */
    public void removeTempToken(String token) {
        redisTemplate.delete(TEMP_TOKEN_PREFIX + token);
        log.debug("Temporary token '{}' removed", token);
    }

    /**
     * Sets the user's password and activates their account.
     *
     * @param token       Temporary token
     * @param newPassword New password
     * @return Status message
     */
    public String setPassword(String token, String newPassword) {
        String email = getEmailByTempToken(token);
        log.debug("Retrieved email '{}' for token '{}'", email, token);

        if (email == null) {
            log.error("Invalid or expired token: {}", token);
            return "Invalid or expired token";
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            log.error("User not found for email: {}", email);
            return "User not found";
        }

        // Update user record
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setEnabled(true); // Activate the user
        user.setEmailVerified(true); // Mark as verified
        userRepository.save(user);

        log.info("Password set and user activated: {}", email);

        // Remove the temporary token
        removeTempToken(token);
        log.debug("Temporary token '{}' removed", token);

        return "Password set successfully!";
    }
}
