package com.study.library.controller.admin;

import com.study.library.aop.annotation.ParamsPrintAspect;
import com.study.library.aop.annotation.ValidAspect;
import com.study.library.dto.RegisterBookReqDto;
import com.study.library.dto.SearchBookReqDto;
import com.study.library.service.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/admin")
public class AdminBookController {

    @Autowired
    private BookService bookService;

    @ValidAspect
    @PostMapping("/book")
    public ResponseEntity<?> saveBook(@Valid @RequestBody RegisterBookReqDto registerBookReqDto, BindingResult bindingResult) {
        bookService.saveBook(registerBookReqDto);
        return ResponseEntity.created(null).body(true);
    }

    @GetMapping("/books")
    public ResponseEntity<?> searchBooks(SearchBookReqDto searchBookReqDto) {
        return ResponseEntity.ok(bookService.searchBooks(searchBookReqDto));
    }

    @GetMapping("/books/count")
    public ResponseEntity<?> getCount(SearchBookReqDto searchBookReqDto) {
        return ResponseEntity.ok(bookService.getBookCount(searchBookReqDto));
    }
}
