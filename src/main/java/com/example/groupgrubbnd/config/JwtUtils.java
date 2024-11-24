package com.example.groupgrubbnd.config;

import com.example.groupgrubbnd.entity.User;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    /**
     * Generates a JWT token for the authenticated user.
     *
     * @param userDetails Authenticated user details
     * @return JWT token as a string
     */
    public String generateJwtToken(UserDetails userDetails) {
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        String roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("roles", roles)
                .claim("userId", ((User) userDetails).getId())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    /**
     * Extracts the email (subject) from the JWT token.
     *
     * @param token JWT token
     * @return Email extracted from the token
     */
    public String getEmailFromJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Validates the JWT token.
     *
     * @param authToken JWT token
     * @return True if valid, false otherwise
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (ExpiredJwtException e) {
            // Token expired
        } catch (UnsupportedJwtException e) {
            // Unsupported token
        } catch (MalformedJwtException e) {
            // Malformed token
        } catch (SignatureException e) {
            // Invalid signature
        } catch (IllegalArgumentException e) {
            // Empty claims string
        }
        return false;
    }

    @PostConstruct
    public void init() {
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("JWT secret must not be null or empty");
        }
    }
}
