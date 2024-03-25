package com.study.library.dto;

import lombok.Data;

@Data
public class RegisterBookReqDto {
    private String isbn;
    private int bookTypeId;
    private int categoryId;
    private String bookName;
    private String authorName;
    private String publisherName;
    private String coverImgUrl;
}
