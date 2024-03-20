package com.study.library.service;

import com.study.library.dto.SigninReqDto;
import com.study.library.dto.SignupReqDto;
import com.study.library.entity.User;
import com.study.library.exception.SaveException;
import com.study.library.jwt.JwtProvider;
import com.study.library.repository.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    @Autowired
    private UserMapper userMapper;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private JwtProvider jwtProvider;

    public boolean isDuplicatedByUsername(String username) {
        return userMapper.findUserByUsername(username) != null;
    }

    @Transactional(rollbackFor = Exception.class) // 모든 예외 롤백
    public void signup(SignupReqDto signupReqDto) {
        int successCount = 0;
        User user = signupReqDto.toEntity(passwordEncoder);

        successCount += userMapper.saveUser(user);
        successCount += userMapper.saveRole(user.getUserId(), 1); // keyProperty="userId", useGeneratedKeys="true"

        if(successCount < 2) {
            throw new SaveException();
        }
    }

    public String signin(SigninReqDto signinReqDto) {
        User user = userMapper.findUserByUsername(signinReqDto.getUsername());
        if(user == null) {
            throw new UsernameNotFoundException("사용자 정보를 확인하세요");
        }
        if(!passwordEncoder.matches(signinReqDto.getPassword(), user.getPassword())) { // 입력, db 비밀번호 매칭
            throw new BadCredentialsException("사용자 정보를 확인하세요");
        }

        return jwtProvider.generateToken(user);
    }
}
