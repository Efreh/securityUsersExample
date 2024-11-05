package com.efr.securityUsersExample.controller;

import com.efr.securityUsersExample.DTO.JwtAuthenticationResponse;
import com.efr.securityUsersExample.DTO.SignInRequest;
import com.efr.securityUsersExample.model.Role;
import com.efr.securityUsersExample.model.User;
import com.efr.securityUsersExample.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class IntegrationTests {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    private String accessToken;
    private String refreshToken;

    @BeforeEach
    void setUp() throws Exception {

        userRepository.deleteAll();

        // Создаём и разблокируем пользователя с ролью SUPER_ADMIN
        User superAdminUser = new User();
        superAdminUser.setUsername("superadmin");
        superAdminUser.setPassword(passwordEncoder.encode("password123")); // захешируйте пароль в реальных тестах
        superAdminUser.setRole(Role.SUPER_ADMIN);
        superAdminUser.setAccountNonLocked(true);
        userRepository.save(superAdminUser);

        // Вход и получение токенов
        SignInRequest signInRequest = new SignInRequest("superadmin", "password123");
        ResultActions result = mockMvc.perform(post("/auth/sign-in")
                        .secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk());

        String responseContent = result.andReturn().getResponse().getContentAsString();
        JwtAuthenticationResponse jwtResponse = objectMapper.readValue(responseContent, JwtAuthenticationResponse.class);
        this.accessToken = jwtResponse.getToken();
        this.refreshToken = jwtResponse.getRefreshToken();
    }

    @Test
    void whenValidToken_thenAccessProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, admin!"));
    }

    @Test
    void whenExpiredToken_thenUnauthorized() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + "expiredAccessToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Невалидный токен."));
    }

    @Test
    void whenValidRefreshToken_thenRefreshAccessToken() throws Exception {
        ResultActions result = mockMvc.perform(get("/auth/refresh-token")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.refreshToken").exists());

        String responseContent = result.andReturn().getResponse().getContentAsString();
        JwtAuthenticationResponse jwtResponse = objectMapper.readValue(responseContent, JwtAuthenticationResponse.class);

        assertThat(jwtResponse.getToken()).isNotNull();
        assertThat(jwtResponse.getRefreshToken()).isNotNull();
    }

    @Test
    void whenInvalidToken_thenUnauthorized() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + "invalidToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Невалидный токен."));
    }

    @Test
    @WithMockUser(authorities = {"MODERATOR"})
    void whenModeratorAccessModeratorEndpoint_thenOk() throws Exception {
        mockMvc.perform(get("/moderator")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, moderator!"));
    }

    @Test
    void whenNoToken_thenForbidden() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true))
                .andExpect(status().isForbidden());
    }
}