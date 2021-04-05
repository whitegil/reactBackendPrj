package com.board.controller;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.common.api.service.ApiService;

@Controller
public class BoardController {
	
	@Autowired
	private ApiService apiService;
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	

	@RequestMapping( value="/api/posts", method = RequestMethod.GET)
	@ResponseBody
	public Map getByIdInJSON22(@RequestParam Map map) throws Exception{

		Map testMap = apiService.selectBeakUser(map);
		
		List<Map<String, String>> postList = new ArrayList();
		
		Map map1 = new HashMap();
		map1.put("_id",  "id11111111");
		
		Map post1 = new HashMap();
		
		post1.put("publishedDate", "20211010");
		post1.put("title", "제목1111");
		post1.put("body",  "내용1111");
		
		Map user1 = new HashMap();
		user1.put("username", "백한길");
		
		post1.put("user", user1);
		post1.put("tags", new ArrayList<>());
		post1.put("_id", "cascascasc");
		
		
		map1.put("post",  post1);
		
//		Map map2 = new HashMap();
//		map2.put("_id",  "id22222222");
		
		postList.add(map1);
		//postList.add(map2);
		
		testMap.put("postlist", postList);
		testMap.put("lastpage", 1);
	
		//"".substring(0, 010);
		
		return testMap;
	}
	
}



