package com.study.library.aop;

import com.study.library.dto.OAuth2SignupReqDto;
import com.study.library.dto.SignupReqDto;
import com.study.library.exception.ValidException;
import com.study.library.repository.UserMapper;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Aspect
@Component
public class ValidAop {

    @Autowired
    private UserMapper userMapper;

    @Pointcut("@annotation(com.study.library.aop.annotation.ValidAspect)")
    private void pointCut() {}

    @Around("pointCut()")
    public Object around(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        String methodName = proceedingJoinPoint.getSignature().getName(); // 메소드이름

        Object[] args = proceedingJoinPoint.getArgs(); // 매개변수들

        BeanPropertyBindingResult bindingResult = null;

        for(Object arg : args) {
            if(arg.getClass() == BeanPropertyBindingResult.class) {
                bindingResult = (BeanPropertyBindingResult) arg; // 원래 (Object)업캐스팅 되어들어가기 때문에 다운캐스팅
            }
        }

        if(methodName.equals("signup")) {
            SignupReqDto signupReqDto = null;

            for(Object arg : args) {
                if(arg.getClass() == SignupReqDto.class) {
                    signupReqDto = (SignupReqDto) arg;
                }
            }
            // 중복일때 
            if(userMapper.findUserByUsername(signupReqDto.getUsername()) != null){
                ObjectError objectError = new FieldError("username", "username", "이미 존재하는 사용자이름입니다.");
                bindingResult.addError(objectError);
            }

        }

        if(methodName.equals("oAuth2Signup")) {
            OAuth2SignupReqDto oAuth2SignupReqDto = null;

            for(Object arg : args) {
                if(arg.getClass() == OAuth2SignupReqDto.class) {
                    oAuth2SignupReqDto = (OAuth2SignupReqDto) arg;
                }
            }
            // 중복일때
            if(userMapper.findUserByUsername(oAuth2SignupReqDto.getUsername()) != null){
                ObjectError objectError = new FieldError("username", "username", "이미 존재하는 사용자이름입니다.");
                bindingResult.addError(objectError);
            }
        }


        

        if(bindingResult.hasErrors()) {  // 에러 조회
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();
            Map<String, String> errorMap = new HashMap<>();
            for(FieldError fieldError : fieldErrors) {
                String fieldName = fieldError.getField();   // DTO 변수명
                String message = fieldError.getDefaultMessage();    // 메세지내용
                errorMap.put(fieldName, message);
            }
            throw new ValidException(errorMap);
        }

        return proceedingJoinPoint.proceed();
    }
}










