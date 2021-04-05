package com.board.service.impl;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.board.service.BoardService;
import com.common.api.dao.ApiDAO;
import com.common.api.service.ApiService;

@Service("boardService")
public class BoardServiceImpl implements BoardService {

	@Autowired
	ApiDAO apiDAO;
	
	@Override
	public Map selectBeakUser(Map paramMap) throws Exception {
		return apiDAO.selectBeakUser(paramMap);
	}

	@Override
	public Map updateUser(Map map) throws Exception {
		
		map.put("usernm", "bbb2104");
		apiDAO.updateUser(map);
		
		return null;
	}


}



