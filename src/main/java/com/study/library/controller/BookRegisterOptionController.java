package com.study.library.controller;

import com.study.library.service.OptionsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/book/option")
public class BookRegisterOptionController {

    @Autowired
    private OptionsService optionsService;

    @GetMapping("/types")
    public ResponseEntity<?> getBookTypes() {
        return ResponseEntity.ok(optionsService.getBookTypes());
    }

    @GetMapping("/categories")
    public ResponseEntity<?> getCategories() {
        return ResponseEntity.ok(optionsService.getCategories());
    }
}
