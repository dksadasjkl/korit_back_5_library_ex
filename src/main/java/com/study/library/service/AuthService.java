package com.study.library.service;

import com.study.library.repository.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserMapper userMapper;

    public boolean isDuplicatedByUsername(String username) {
        return userMapper.findUserByUsername(username) != null;
    }

}
