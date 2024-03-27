package com.study.library.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class SearchBookCountRespDto {
    private int totalCount;
    private int maxPageNumber;
}
