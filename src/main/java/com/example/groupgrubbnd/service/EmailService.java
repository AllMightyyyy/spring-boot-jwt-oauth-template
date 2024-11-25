package com.example.groupgrubbnd.service;

import com.example.groupgrubbnd.entity.AccountVerification;
import com.example.groupgrubbnd.entity.User;
import com.example.groupgrubbnd.helper.EmailSender;
import com.example.groupgrubbnd.model.EmailDetails;
import com.example.groupgrubbnd.repository.AccountVerificationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Service responsible for sending emails.
 */
@Slf4j
@Service
public class EmailService {

    private final EmailSender emailSender;

    private final AccountVerificationRepository accountVerificationRepository;

    private final Environment environment;

    @Value("${SERVER.ADDRESS}")
    private String serverAddress;

    @Value("${SERVER.PORT}")
    private String serverPort;

    @Autowired
    public EmailService(EmailSender emailSender, AccountVerificationRepository accountVerificationRepository, Environment environment) {
        this.emailSender = emailSender;
        this.environment = environment;
        this.accountVerificationRepository = accountVerificationRepository;
    }

    /**
     * Sends an account verification email to the user with the provided token.
     *
     * @param user  User to send the email to
     * @param token Verification token
     */
    public void sendAccountVerificationEmail(User user, String token) {
        String verificationLink = String.format("http://%s:%s/api/auth/verify?token=%s",
                serverAddress, serverPort, token);

        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setRecipient(user.getEmail());
        emailDetails.setSubject("Account Verification");
        String body = "Thank you for registering. Please verify your account by clicking the link below:\n" + verificationLink;
        emailDetails.setBody(body);

        emailSender.sendSimpleMail(emailDetails);
    }

    /**
     * Sends a password reset email to the user with the provided token.
     *
     * @param user  User to send the email to
     * @param token Password reset token
     */
    public void sendPasswordResetEmail(User user, String token) {
        String resetLink = String.format("http://%s:%s/changepassword?token=%s",
                serverAddress, serverPort, token);

        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setRecipient(user.getEmail());
        emailDetails.setSubject("Reset Password");
        String body = "Click the link to reset your password: " + resetLink;
        emailDetails.setBody(body);

        emailSender.sendSimpleMail(emailDetails);
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
}
