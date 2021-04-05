package com.common.api.service;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

public interface ApiService {
	
	public Map selectBeakUser (Map paramMap) throws Exception;

	public Map updateUser(Map map)  throws Exception;
	
}



