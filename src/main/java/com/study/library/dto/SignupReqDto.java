package com.study.library.dto;

import lombok.Data;

@Data
public class SignupReqDto {
    private String username;
    private String password;
    private String name;
    private String email;
}
