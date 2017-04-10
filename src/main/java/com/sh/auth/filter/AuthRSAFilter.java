package com.sh.auth.filter;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.sh.auth.crypto.RSAKeys;
import com.sh.auth.crypto.RSARepository;

@Component
public class AuthRSAFilter extends GenericFilterBean {
	
	@Autowired
	private RSAKeys keys;
	
	@Autowired
	private RSARepository repo;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException 
	{
		
		HttpServletRequest req =(HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		
		Pattern pat = Pattern.compile("^\\/appz.*|^\\/jsLib.*|^\\/fonts.*|^\\/css.*|^\\/login\\.html");
		Matcher match = pat.matcher(req.getRequestURI());
		
		if(!match.matches())
		{
			System.out.println(req.getRequestURI());
			try 
			{
				Cookie coo = repo.isCookiePresent(req);
				if(coo != null)
				{
					boolean isValid = keys.validateCookie(coo);
					if(!isValid)
					{
						resp.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
						resp.setHeader("Location", "/login.html");
					}
				}
				else
				{
					resp.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
					resp.setHeader("Location", "/login.html");
				}
				
			} 
			catch (Exception e) {
				
				e.printStackTrace();
			}
		}

		chain.doFilter(req, resp);
		
	}
	
	
	
	
	
}
