package com.efr.securityUsersExample.controller;

import com.efr.securityUsersExample.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasAuthority('SUPER_ADMIN')")
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<String> administratum() {
        return ResponseEntity.ok("Hello, admin!");
    }

    @GetMapping("/unban/{username}")
    public ResponseEntity<String> unbanUser(@PathVariable String username) {
        boolean isUnbanned = userService.unbanUser(username);
        if (isUnbanned) {
            return ResponseEntity.ok("Пользователь " + username + " разблокирован");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED)
                    .body("Пользователь " + username + " не заблокирован");
        }
    }
}
