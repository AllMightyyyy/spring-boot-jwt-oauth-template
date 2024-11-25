package com.example.groupgrubbnd.service;

import com.example.groupgrubbnd.config.JwtUtils;
import com.example.groupgrubbnd.entity.OauthToken;
import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.model.LoginResponseDTO;
import com.example.groupgrubbnd.repository.OauthTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service responsible for managing tokens.
 */
@Service
public class TokenService {

    private final JwtUtils jwtUtils;
    private final OauthTokenRepository oauthTokenRepository;
    private final RedisTemplate<String, String> redisTemplate;

    private static final String TEMP_TOKEN_PREFIX = "temp_token:";

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Autowired
    public TokenService(JwtUtils jwtUtils,
                        OauthTokenRepository oauthTokenRepository,
                        RedisTemplate<String, String> redisTemplate) {
        this.jwtUtils = jwtUtils;
        this.oauthTokenRepository = oauthTokenRepository;
        this.redisTemplate = redisTemplate;
    }

    /**
     * Generates JWT token for the user.
     *
     * @param user Authenticated user
     * @return JWT token string
     */
    public String generateJwtToken(User user) {
        return jwtUtils.generateJwtToken(user);
    }

    /**
     * Generates a refresh token.
     *
     * @return Refresh token string
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generates tokens for the user and saves them in the database.
     *
     * @param user Authenticated user
     * @return LoginResponseDTO containing tokens
     */
    public LoginResponseDTO generateAndSaveTokens(User user) {
        String jwtToken = generateJwtToken(user);
        String refreshToken = generateRefreshToken();
        LocalDateTime expirationTime = LocalDateTime.now().plusHours(1);

        OauthToken oauthToken = new OauthToken();
        oauthToken.setAccessToken(jwtToken);
        oauthToken.setRefreshToken(refreshToken);
        oauthToken.setExpirationTime(expirationTime);
        oauthToken.setUser(user);

        oauthTokenRepository.save(oauthToken);

        LoginResponseDTO dto = new LoginResponseDTO();
        dto.setAccessToken(jwtToken);
        dto.setRefreshToken(refreshToken);
        dto.setExpirationTime(expirationTime);

        return dto;
    }

    /**
     * Generates a JWT token for the authenticated user.
     *
     * @param user Authenticated user
     * @return LoginResponseDTO containing the JWT token
     */
    public LoginResponseDTO generateTokenForUser(User user) {
        // Generate the JWT token using JwtUtils
        String jwtToken = jwtUtils.generateJwtToken(user);

        // Calculate expiration time
        LocalDateTime expirationTime = LocalDateTime.now().plus(Duration.ofMillis(jwtExpirationMs));

        // Construct the response DTO
        LoginResponseDTO dto = new LoginResponseDTO();
        dto.setAccessToken(jwtToken);
        dto.setExpirationTime(expirationTime);

        return dto;
    }

    /**
     * Refreshes access token using the refresh token.
     *
     * @param refreshToken Refresh token string
     * @return New LoginResponseDTO containing tokens
     */
    public LoginResponseDTO refreshAccessToken(String refreshToken) {
        OauthToken oauthToken = oauthTokenRepository.findByRefreshToken(refreshToken);
        if(oauthToken == null || oauthToken.getExpirationTime().isBefore(LocalDateTime.now())) {
            throw new BadCredentialsException("Invalid or expired refresh token");
        }

        // Delete old tokens
        oauthTokenRepository.delete(oauthToken);

        // Generate new tokens
        return generateAndSaveTokens(oauthToken.getUser());
    }

    /**
     * Logs out the user by deleting their OAuth tokens.
     *
     * @param user User to log out
     * @return Status message
     */
    public String logout(User user) {
        oauthTokenRepository.deleteByUser(user);
        return "Logged out successfully!";
    }

    /**
     * Stores a temporary token in Redis mapped to the user's email.
     *
     * @param token Temporary token
     * @param email User's email
     */
    public void storeTempToken(String token, String email) {
        redisTemplate.opsForValue().set(TEMP_TOKEN_PREFIX + token, email, 15, TimeUnit.MINUTES);
    }

    /**
     * Retrieves email associated with a temporary token from Redis.
     *
     * @param token Temporary token
     * @return User's email or null if not found
     */
    public String getEmailByTempToken(String token) {
        return redisTemplate.opsForValue().get(TEMP_TOKEN_PREFIX + token);
    }

    /**
     * Removes a temporary token from Redis after use.
     *
     * @param token Temporary token
     */
    public void removeTempToken(String token) {
        redisTemplate.delete(TEMP_TOKEN_PREFIX + token);
    }
}
