package com.study.library.dto;

import com.study.library.entity.User;
import lombok.Data;

@Data
public class SigninReqDto {
    private String username;
    private String password;
}
