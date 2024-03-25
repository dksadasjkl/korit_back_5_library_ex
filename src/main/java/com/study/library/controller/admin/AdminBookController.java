package com.study.library.controller.admin;

import com.study.library.aop.annotation.ParamsPrintAspect;
import com.study.library.dto.RegisterBookReqDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminBookController {

    @ParamsPrintAspect
    @PostMapping("/book")
    public ResponseEntity<?> saveBook(@RequestBody RegisterBookReqDto registerBookReqDto) {
        return ResponseEntity.created(null).body(null);
    }
}
