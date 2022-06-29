package com.appvam.api.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

@AllArgsConstructor
@Data
public class JwtResponse {
    private Long id;
    private String token;
    private String type;
    private String username;
    private String email;
    private Set<String> roles;
}
