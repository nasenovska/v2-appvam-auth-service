package com.appvam.api.payload.request;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;

@Data
public class SignupRequest {
    @NotBlank(message = "Name should not be blank")
    @Size(min = 2, max = 100, message = "Name should be between 2 and 100 characters")
    private String name;

    @NotBlank(message = "Username should not be blank")
    @Size(min = 3, max = 20, message = "Username should be between 3 and 20 characters")
    private String username;

    @NotBlank(message = "Email should not be blank")
    @Size(min = 4, max = 50, message = "Email should be between 4 and 50 characters")
    @Email
    private String email;

    private Set<String> roles;

    @NotBlank(message = "Password should not be blank")
    @Size(min = 6, max = 40,  message = "Name should be between 6 and 40 characters")
    private String password;

    @Size(max = 12, message = "Phone should be less than 12 characters")
    private String phone;

    @Size(max = 50, message = "Address should be less than 50 characters")
    private String address;
}
