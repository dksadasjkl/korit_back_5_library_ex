package com.study.library.controller;

import com.study.library.security.PrincipalUser;
import com.study.library.service.AccountMailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequestMapping("/mail")
public class AccountMailController {

    @Autowired
    private AccountMailService accountMailService;

    @PostMapping("/send")
    @ResponseBody
    public ResponseEntity<?> send() {
        return ResponseEntity.ok(accountMailService.sendAuthMail());
    }

    @GetMapping("/authenticate")
    public String resultPage(Model model, @RequestParam String authToken) {
        Map<String, Object> resultMap = accountMailService.authenticate(authToken);
        model.addAllAttributes(resultMap);
        return "result_page";
    }
}
