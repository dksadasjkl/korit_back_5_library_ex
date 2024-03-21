package com.study.library.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2 {
    private int oAuth2Id;
    private String oAuth2Name;
    private int userId;
    private String providerName;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
}
