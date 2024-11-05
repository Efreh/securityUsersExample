package com.efr.securityUsersExample.controller;

import com.efr.securityUsersExample.DTO.JwtAuthenticationResponse;
import com.efr.securityUsersExample.DTO.SignInRequest;
import com.efr.securityUsersExample.DTO.SignUpRequest;
import com.efr.securityUsersExample.service.AuthenticationService;
import com.efr.securityUsersExample.service.JwtService;
import com.efr.securityUsersExample.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserService userService;

    @PostMapping("/sign-up")
    public ResponseEntity<JwtAuthenticationResponse> signUp(@RequestBody @Valid SignUpRequest request) {
        JwtAuthenticationResponse response = authenticationService.signUp(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response); // 201 Created
    }

    @PostMapping("/sign-in")
    public ResponseEntity<JwtAuthenticationResponse> signIn(@RequestBody @Valid SignInRequest request) {
        JwtAuthenticationResponse response = authenticationService.signIn(request);
        return ResponseEntity.ok(response); // 200 OK
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(@RequestHeader("Authorization") String refreshTokenHeader) {
        String refreshToken = refreshTokenHeader.substring(7).trim();

        if (jwtService.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String username = jwtService.extractUserName(refreshToken);
        UserDetails userDetails = userService.getByUsername(username);

        JwtAuthenticationResponse response = JwtAuthenticationResponse.builder()
                .token(jwtService.generateToken(userDetails))
                .refreshToken(jwtService.generateRefreshToken(userDetails))
                .build();

        return ResponseEntity.ok(response);
    }
}