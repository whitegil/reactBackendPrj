package com.common.api.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.common.api.service.ApiService;

@Repository("apiDAO")
public class ApiDAO {
	
	@Autowired
	private SqlSession sqlSession;

	public Map selectBeakUser(Map paramMap) throws Exception {
		return sqlSession.selectOne("com.common.login.dao.MemberDao.getUser", "test");
	}

	public int updateUser(Map map) throws Exception {
		return sqlSession.update("com.common.login.dao.MemberDao.updateUser", map);
	}
	
}



