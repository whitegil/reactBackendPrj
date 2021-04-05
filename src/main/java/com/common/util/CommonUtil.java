package com.common.util;

import java.security.Key;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.validation.Errors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class CommonUtil {

    
	public static String encryptPassword(String password, String id) throws Exception {
    	
		if (password == null) return "";
		if (id == null) return ""; // KISA 보안약점 조치 (2018-12-11, 신용호)
		
		byte[] hashValue = null; // 해쉬값
	
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		md.reset();
		md.update(id.getBytes());
		
		hashValue = md.digest(password.getBytes());
	
		return new String(Base64.encodeBase64(hashValue));
    }

}



