package com.efr.securityUsersExample.service;

import com.efr.securityUsersExample.DTO.JwtAuthenticationResponse;
import com.efr.securityUsersExample.DTO.SignUpRequest;
import com.efr.securityUsersExample.DTO.SignInRequest;
import com.efr.securityUsersExample.exceptions.InvalidTokenException;
import com.efr.securityUsersExample.exceptions.LockedException;
import com.efr.securityUsersExample.model.Role;
import com.efr.securityUsersExample.model.User;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public JwtAuthenticationResponse signUp(SignUpRequest request) {
        logger.info("Attempting to sign up user: {}", request.getUsername());

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .isAccountNonLocked(true)
                .build();

        userService.create(user);

        logger.info("User '{}' successfully signed up", request.getUsername());

        String jwt = jwtService.generateToken(user);
        String refreshJwt = jwtService.generateRefreshToken(user);
        logger.info("Generated JWT for user '{}': {}", request.getUsername(), jwt);

        return new JwtAuthenticationResponse(jwt,refreshJwt);
    }

    public JwtAuthenticationResponse signIn(SignInRequest request) {
        User user = userService.getByUsername(request.getUsername());

        if (!user.isAccountNonLocked()) {
            logger.warn("User '{}' account is locked due to too many failed login attempts.", request.getUsername());
            throw new LockedException("Аккаунт заблокирован из-за слишком большого количества неудачных попыток входа.");
        }

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            ));
            logger.info("User '{}' successfully signed in", request.getUsername());

            userService.resetFailedLoginAttempts(user);

            String jwt = jwtService.generateToken(user);
            String refreshJwt = jwtService.generateRefreshToken(user);
            logger.info("Generated JWT for user '{}': {}", request.getUsername(), jwt);

            return new JwtAuthenticationResponse(jwt,refreshJwt);

        } catch (BadCredentialsException e) {
            logger.warn("User '{}' failed to sign in: {}", request.getUsername(), e.getMessage());

            userService.incrementFailedLoginAttempts(user);

            throw new BadCredentialsException("Неверные учетные данные.");
        }
    }

    public JwtAuthenticationResponse refreshJwtToken(String refreshToken) {
        UserDetails userDetails = userService.getCurrentUser();

        if (jwtService.isRefreshTokenValid(refreshToken, userDetails)) {
            String newAccessToken = jwtService.generateToken(userDetails);
            return JwtAuthenticationResponse.builder()
                    .token(newAccessToken)
                    .build();
        } else {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }
    }
}