package com.efr.securityUsersExample.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class LoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String username = request.getParameter("username"); // Извлечение имени пользователя из параметров запроса
        logger.info("Incoming request: {} {} from user: {}", request.getMethod(), request.getRequestURI(), username); // Логирование входящего запроса

        try {
            filterChain.doFilter(request, response); // Продолжение цепочки фильтров
        } finally {
            logger.info("Completed request: {} {}", request.getMethod(), request.getRequestURI());
        }
    }
}