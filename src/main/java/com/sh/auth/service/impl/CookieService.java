package com.sh.auth.service.impl;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.sh.auth.crypto.DecodedCookie;
import com.sh.auth.crypto.RSAKeys;
import com.sh.auth.crypto.RSARepository;

@Service
public class CookieService {

	@Autowired
	private RSAKeys rsaKeys;
	
	@Autowired
	private RSARepository repo;
	
	@Value("${expiration.time}")
	private String expire;
	
	
	public Long getExpirationTime(HttpServletRequest req) throws Exception
	{
		
		Cookie coo = repo.isCookiePresent(req);
		if(coo != null)
		{
			DecodedCookie mapa = rsaKeys.decodeCookie(coo);
			String s = mapa.getCreation();
			long creation = Long.parseLong(s);
			long exp = Long.parseLong(expire)*1000;
			return creation + exp;	
		}
		else
		{
			throw new Exception("An Error Ocurred");
		}
		
	}
	
	
	
}
