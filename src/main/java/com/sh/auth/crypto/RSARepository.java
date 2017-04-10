package com.sh.auth.crypto;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;


public class RSARepository {

	private  String REP_PATH;
	
	private String COOKIE_NAME;
	
	@Value("${expiration.time}")
	private String expire;

	public RSARepository(String rEP_PATH, String cOOKIE_NAME) {
		
		this.REP_PATH = rEP_PATH;
		this.COOKIE_NAME = cOOKIE_NAME;
	}

	public  void writeCert(KeyInfo info) throws JsonGenerationException, JsonMappingException, IOException
	{
		ObjectMapper mapper = new ObjectMapper();
		File json = new File(REP_PATH);
		List<KeyInfo> lsKeys = new ArrayList<KeyInfo>();
		if(json.exists())
		{
			lsKeys = mapper.readValue(json, new TypeReference<List<KeyInfo>>() {});
			
		}
		lsKeys.add(info);
		mapper.writeValue(json, lsKeys);
		
	}
	
	public  List<KeyInfo> readKeys() throws JsonParseException, JsonMappingException, IOException
	{
		File json = new File(REP_PATH);
		List<KeyInfo> lsKeys = null;
		ObjectMapper mapper = new ObjectMapper();
		if(json.exists())
		{
			lsKeys = mapper.readValue(json, new TypeReference<List<KeyInfo>>() {});
		}
		return lsKeys;
	}
	
	public  KeyInfo readKeys(String user) throws JsonParseException, JsonMappingException, IOException
	{
		File json = new File(REP_PATH);
		List<KeyInfo> lsKeys = null;
		ObjectMapper mapper = new ObjectMapper();
		KeyInfo res = null;
		if(json.exists())
		{
			lsKeys = mapper.readValue(json, new TypeReference<List<KeyInfo>>() {});
			for(KeyInfo k : lsKeys)
			{
				if(user.equals(k.getUser()))
				{
					res = k;
					break;
				}
			}
		}
		return res;
	}
	
	public  Cookie createCookie(String user) throws Exception
	{
		
		final KeyInfo key = readKeys(user);
		
		
		Cookie cookie = new Cookie(COOKIE_NAME, Base64.encodeBase64String(key.getUser().getBytes())+"#"+key.getKey()+"#"+System.currentTimeMillis());
		cookie.setDomain("dev.com");
		cookie.setPath("/");
		cookie.setMaxAge(Integer.parseInt(expire));
		return cookie;
	}
	
	public  Cookie isCookiePresent(HttpServletRequest req)
	{
		Cookie[] cookies = req.getCookies();
		if(cookies != null)
		{
			for(Cookie c : cookies)
			{
				if(COOKIE_NAME.equals(c.getName()))
				{
					return c;
				}
			}
		}
		return null;
	}
	
	
	
}
