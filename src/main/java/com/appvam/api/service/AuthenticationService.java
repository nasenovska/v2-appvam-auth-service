package com.appvam.api.service;

import com.appvam.api.payload.request.LoginRequest;
import com.appvam.api.payload.request.SignupRequest;
import com.appvam.api.payload.response.JwtResponse;
import com.appvam.api.payload.response.MessageResponse;

public interface AuthenticationService {

    JwtResponse login(LoginRequest loginRequest);

    MessageResponse signup(SignupRequest signUpRequest);

    MessageResponse tokenResponse(String token);
}
