package com.common.login.service.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.common.login.service.LoginService;
import com.common.login.service.dao.LoginDAO;
import com.common.util.CommonUtil;
import com.common.util.JwtUtil;

@Service("loginService")
public class LoginServiceImpl implements LoginService {

	@Autowired
	LoginDAO loginDAO;

	@Override
	public Map userLogin(Map map) throws Exception {
		
		Map resultMap = new HashMap();
		
		String enpassword = CommonUtil.encryptPassword(map.get("password").toString(), map.get("username").toString());
		map.put("userId", map.get("username"));
		map.put("password", enpassword);
		
		int loginCnt = loginDAO.userLoginCnt(map);
		
		if(loginCnt <= 0) {
			resultMap.put("status", 401);
			resultMap.put("error", "로그인실패찡");
			
			
		}else {
			
			resultMap = map;
			
			String token = JwtUtil.createToken(map.get("username").toString(), resultMap, true, null);
			resultMap.put("loginToken", token);
		}
		
		return resultMap;
	}

	@Override
	public Map userCheck(Map map) throws Exception {
		
		Map resultMap = new HashMap();
		
//		if(map.get("username") == null) {
//			resultMap.put("status", 401);
//			resultMap.put("error", "체크실패");
//		}
		
		return resultMap;
	}

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("user_id".equals(username)) {
            return new User("user_id", "$2a$10$m/enYHaLsCwH2dKMUAtQp.ksGOA6lq7Fd2pnMb4L.yT4GyeAPRPyS", new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }

	@Override
	public Map insertUser(Map map) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map updateGoogleLogin(Map map) throws Exception {
		
		Map resultMap = new HashMap();
		
		Map userInfo = (Map)map.get("userInfo");
		Map tokenObj = (Map)userInfo.get("profileObj");
		
		String accessToken = userInfo.get("accessToken").toString(); 
		String userName = tokenObj.get("name").toString();
		String email = tokenObj.get("email").toString();
		
		Map userMap = new HashMap();
		userMap.put("email", email);
		userMap.put("userName", userName);
		
		int userGoogleLogin = loginDAO.updateGoogleLogin(userMap);
		
		String token = JwtUtil.createToken(userName, resultMap, true, null);
		resultMap.put("loginToken", token);
		
		return resultMap;
	}

}



