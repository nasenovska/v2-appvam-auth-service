package com.appvam.api.service;

import com.appvam.api.models.Role;
import com.appvam.api.models.Roles;
import com.appvam.api.models.User;
import com.appvam.api.payload.request.LoginRequest;
import com.appvam.api.payload.request.SignupRequest;
import com.appvam.api.payload.response.JwtResponse;
import com.appvam.api.payload.response.MessageResponse;
import com.appvam.api.repository.RoleRepository;
import com.appvam.api.repository.UserRepository;
import com.appvam.api.security.jwt.JwtUtils;
import com.appvam.api.security.services.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Value(value = "${token-type}")
    private String type;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    @Override
    public JwtResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        return new JwtResponse(userDetails.getId(), jwt, type, userDetails.getUsername(), userDetails.getEmail(), roles);
    }

    @Override
    public MessageResponse signup(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse(400, "Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse(400, "Email is already in use!");
        }

        User user = new User(
                signUpRequest.getName(),
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getPhone(),
                signUpRequest.getAddress()
        );

        Set<String> requestedRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (requestedRoles == null) {
            Role userRole = roleRepository.findByName(Roles.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Role is not found."));
            roles.add(userRole);
        } else {
            requestedRoles.forEach(role -> {
                Role userRole = roleRepository.findByName(role)
                        .orElseThrow(() -> new RuntimeException("Role is not found."));
                roles.add(userRole);
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return new MessageResponse(200, "User registered successfully!");
    }

    @Override
    public MessageResponse tokenResponse(String token) {
        if (token == null) {
            return new MessageResponse(400, "Token not provided.");
        }

        token = token.trim();

        if (token.isEmpty()) {
            return new MessageResponse(400, "Token contains only whitespaces.");
        }

        return jwtUtils.isTokenValid(token)
                ? new MessageResponse(200, "Provided token is valid.")
                : new MessageResponse(403, "Provided token is not valid.");
    }
}
