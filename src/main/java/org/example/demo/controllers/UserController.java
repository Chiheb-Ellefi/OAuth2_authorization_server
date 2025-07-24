package org.example.demo.controllers;

import org.example.demo.entities.User;
import org.example.demo.services.CustomUserDetailsManager;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final CustomUserDetailsManager customUserDetailsManager;
    private final PasswordEncoder passwordEncoder;
    public UserController(CustomUserDetailsManager customUserDetailsManager,PasswordEncoder passwordEncoder) {
        this.customUserDetailsManager = customUserDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }
    @GetMapping
    public ResponseEntity<UserDetails> index() {
        UserDetails userDetails = User.builder()
                .username("admin")
                .password("admin")
                .role("ADMIN")
                .build();

        customUserDetailsManager.createUser(userDetails);
        return ResponseEntity.ok(userDetails);
    }
}
