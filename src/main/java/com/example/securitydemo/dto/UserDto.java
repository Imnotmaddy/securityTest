package com.example.securitydemo.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
@AllArgsConstructor
public class UserDto {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
