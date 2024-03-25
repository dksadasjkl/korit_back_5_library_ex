package com.study.library.repository;

import com.study.library.entity.BookType;
import com.study.library.entity.Category;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface OptionsMapper {
    public List<BookType> getAllBookTypes();
    public List<Category> getAllCategories();
}
