package com.sh.auth.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sh.auth.provider.User;
import com.sh.auth.service.SignInService;
import com.sh.auth.service.impl.CookieService;


@RestController
public class AuthCtrl {

	@Autowired
	private SignInService service;
	
	@Autowired
	private CookieService cookieServ;
	
	@RequestMapping(path="/signIn",method=RequestMethod.POST)
	public String signIn(@RequestBody User user) throws Exception
	{
		if(service.createUser(user))
		{
			return "Sucessfull";
		}
		else
		{
			return "error";
		}
			
		 
	}
	@RequestMapping("/exam")
	public String example(HttpServletRequest req,HttpServletResponse resp)
	{
		try {
			long res = cookieServ.getExpirationTime(req);
			return String.valueOf(res);
		} catch (Exception e) {
			e.printStackTrace();
			return e.getMessage();
		}
	}
	
}
