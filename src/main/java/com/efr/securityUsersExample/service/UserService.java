package com.efr.securityUsersExample.service;

import com.efr.securityUsersExample.exceptions.UserNotFoundException;
import com.efr.securityUsersExample.exceptions.UserWithNameExistsException;
import com.efr.securityUsersExample.model.User;
import com.efr.securityUsersExample.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public User save(User user) {
        return userRepository.save(user);
    }

    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new UserWithNameExistsException("Пользователь с таким именем уже существует");
        }

        return save(user);
    }

    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));
    }

    public User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }

    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    public void incrementFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= 5) {
            user.setAccountNonLocked(false);
        }
        save(user);
    }

    public void resetFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(0);
        save(user);
    }

    public boolean unbanUser(String username) {
        User repositoryUser = getByUsername(username);
        if (!repositoryUser.isAccountNonLocked()) {
            repositoryUser.setFailedLoginAttempts(0);
            repositoryUser.setAccountNonLocked(true);
            save(repositoryUser);
            return true;
        }
        return false;
    }
}
