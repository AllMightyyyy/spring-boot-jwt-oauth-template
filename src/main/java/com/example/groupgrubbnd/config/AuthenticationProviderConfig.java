package com.example.groupgrubbnd.config;

import com.example.groupgrubbnd.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AuthenticationProviderConfig {

    @Bean
    public AuthenticationProvider customAuthenticationProvider(CustomUserDetailsService userDetailsService,
                                                               PasswordEncoder passwordEncoder) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
    }
}
