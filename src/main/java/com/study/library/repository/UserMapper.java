package com.study.library.repository;

import com.study.library.entity.RoleRegister;
import com.study.library.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper {
    public User findUserByUsername(String username);
    public int saveUser(User user);
    public int saveRole(@Param("userId") int userId, @Param("roleId") int roleId);
    public RoleRegister findRoleRegisterByUserIdAndRoleId(@Param("userId") int userId, @Param("roleId") int roleId);

}
