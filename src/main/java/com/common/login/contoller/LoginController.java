package com.common.login.contoller;

import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.common.login.service.LoginService;
import com.common.login.service.MemberService;

@RestController
public class LoginController {
	
    @Autowired
    private MemberService memberService;
    
    @Autowired
    private LoginService loginService;

    @GetMapping("/")
    public String homeView() {
        return "login/home";
    }

    @GetMapping("/login")
    public String loginView() {
        return "login/login";
    }

    @GetMapping("/signup")
    public String signupView() {
        return "login/signup";
    }

    @PostMapping("/signup")
    public String signup(Map memberTO) {
        memberService.save(memberTO);
        return "redirect:/login";
    }

    @PreAuthorize("hasRole('ROLE_MEMBER')")
    @GetMapping("/member/info")
    public String userInfoView() {
        return "login/user_info";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminView() {
        return "login/admin";
    }

    @GetMapping("/denied")
    public String deniedView() {
        return "login/denied";
    }
    
//    @RequestMapping( value="/api/auth/login", method = RequestMethod.POST)
//	@ResponseBody
//	public Map login(@RequestBody Map map) throws Exception{
//		
//		Map testMap = loginService.userLogin(map);
//		return testMap ;
//	}
    
    
    
	@RequestMapping( value="/api/auth/login", method = RequestMethod.POST)
	@ResponseBody
	public Map login(@RequestBody Map map, HttpServletResponse response) throws Exception{
		
		Map loginMap = loginService.userLogin(map);
		
		Cookie cookieToken = new Cookie("loginToken", loginMap.get("loginToken").toString());
		cookieToken.setPath("/");
		cookieToken.setHttpOnly(true);
		cookieToken.setMaxAge(1800);
		
		System.out.println("tttttttttt");
		
		response.addCookie(cookieToken);
		
		return loginMap;
	}
	
	@RequestMapping( value="/api/auth/check", method = RequestMethod.GET)
	@ResponseBody
	public Map userCheck( Map map, HttpServletRequest httpServletRequest) throws Exception{
		
		Map testMap = loginService.userCheck(map);
		return testMap ;
	}
	
	@RequestMapping( value="/api/auth/register", method = RequestMethod.POST)
	@ResponseBody
	public Map userRegister(@RequestBody Map map, HttpServletResponse response) throws Exception{
		
		Map loginMap = loginService.userLogin(map);
		
		Cookie cookieToken = new Cookie("loginToken", loginMap.get("loginToken").toString());
		cookieToken.setPath("/");
		cookieToken.setHttpOnly(true);
		cookieToken.setMaxAge(1800);
		
		response.addCookie(cookieToken);
		
		return loginMap;
	}
	
	
    
	
}
