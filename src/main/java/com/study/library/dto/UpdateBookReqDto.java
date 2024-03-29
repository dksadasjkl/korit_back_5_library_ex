package com.study.library.dto;

import com.study.library.entity.Book;
import lombok.Data;

@Data
public class UpdateBookReqDto {
    private int bookId;
    private String bookName;
    private String authorName;
    private String publisherName;
    private String isbn;
    private int bookTypeId;
    private int categoryId;
    private String coverImgUrl;

    public Book toEntity() {
        return Book.builder()
                .bookId(bookId)
                .bookName(bookName)
                .authorName(authorName)
                .publisherName(publisherName)
                .isbn(isbn)
                .bookTypeId(bookTypeId)
                .categoryId(categoryId)
                .coverImgUrl(coverImgUrl)
                .build();
    }
}
