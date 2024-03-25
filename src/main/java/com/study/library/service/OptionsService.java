package com.study.library.service;

import com.study.library.entity.BookType;
import com.study.library.entity.Category;
import com.study.library.repository.OptionsMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OptionsService {
    @Autowired
    private OptionsMapper optionsMapper;

    public List<BookType> getBookTypes () {
        return optionsMapper.getAllBookTypes();
    }

    public List<Category> getCategories() {
        return optionsMapper.getAllCategories();
    }
}
