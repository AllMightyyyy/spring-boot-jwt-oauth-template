package com.example.groupgrubbnd.service;

import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user == null || !user.isEnabled()) {
            throw new UsernameNotFoundException("User not found or not enabled");
        }
        return user;
    }
}

