package com.study.library.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Book {
    private int bookId;
    private String bookName;
    private String authorName;
    private String publisherName;
    private String isbn;
    private int bookTypeId;
    private int categoryId;
    private String coverImgUrl;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
}
