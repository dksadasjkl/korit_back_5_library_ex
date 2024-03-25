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
public class Category {
    private int categoryId;
    private String categoryName;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
}
