package com.efr.securityUsersExample.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/welcome")
@RequiredArgsConstructor
public class WelcomeController {

    @GetMapping
    public ResponseEntity<String> example() {
        return ResponseEntity.ok("Hello, world!"); // 200 OK
    }
}