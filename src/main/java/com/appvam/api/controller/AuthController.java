package com.appvam.api.controller;

import com.appvam.api.payload.request.LoginRequest;
import com.appvam.api.payload.request.SignupRequest;
import com.appvam.api.payload.response.MessageResponse;
import com.appvam.api.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v2/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        return ResponseEntity.ok(authenticationService.login(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

        MessageResponse response = authenticationService.signup(signUpRequest);

        return ResponseEntity
                .status(response.getCode())
                .body(response);
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader(required = false, value = "Authorization") String token) {

        MessageResponse response = authenticationService.tokenResponse(token);

        return ResponseEntity
                .status(response.getCode())
                .body(response);
    }
}
