package com.study.library.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class SearchBookRespDto {
    private int bookId;
    private String bookName;
    private String authorName;
    private String publisherName;
    private String isbn;
    private int bookTypeId;
    private String bookTypeName;
    private int categoryId;
    private String categoryName;
    private String coverImgUrl;

}
