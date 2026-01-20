
package com.example.Backend.controller;

import com.example.Backend.model.User;
import com.example.Backend.repository.UserRepository;
import com.example.Backend.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:5173")
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(UserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    // POST /auth/register  body: { "username": "...", "password": "..." }
    @PostMapping("/register")
    public Map<String, String> register(@RequestBody Map<String, String> body) {
        String username = safe(body.get("username"));
        String password = safe(body.get("password"));

        if (username.isBlank() || password.isBlank()) {
            throw new RuntimeException("Username and password are required");
        }
        if (users.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }

        User u = new User(username, encoder.encode(password));
        users.save(u);

        String token = jwt.generateToken(u.getUsername());
        return Map.of("token", token, "username", u.getUsername());
    }

    // POST /auth/login  body: { "username": "...", "password": "..." }
    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> body) {
        String username = safe(body.get("username"));
        String password = safe(body.get("password"));

        var u = users.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!encoder.matches(password, u.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwt.generateToken(u.getUsername());
        return Map.of("token", token, "username", u.getUsername());
    }

    private String safe(String v) { return v == null ? "" : v.trim(); }
}
