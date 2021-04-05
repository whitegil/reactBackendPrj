package com.common.login.mapper;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface MemberMapper {

	Map getUser(String userId);
}
