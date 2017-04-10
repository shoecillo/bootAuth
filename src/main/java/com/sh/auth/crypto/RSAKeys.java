package com.sh.auth.crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;


public class RSAKeys 
{
	@Autowired
	private RSARepository repo;
	
	@Value("${keys.keystore.path}")
	private  String ksPath;
	
	private KeyStore KS = null;
	
	@Value("${keys.keystore.pwd}")
	private String pwd;
	
	@Value("${keys.keystore.alias}")
	private String alias;
	
	@Value("${expiration.time}")
	private String expire;
	
	private KeyPair keyPair = null;
	
	public RSAKeys(String ksPath,String pwd, String alias) {
		
		try 
		{
			this.ksPath = ksPath;
			this.pwd=pwd;
			this.alias = alias;
			
			KS = KeyStore.getInstance("JKS");
			InputStream is = new FileInputStream(ksPath);
			KS.load(is, pwd.toCharArray());
			is.close();	
			getKS();
		}
		catch (FileNotFoundException e) {	
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		} catch (CertificateException e) {
			
			e.printStackTrace();
		} catch (IOException e) {
			
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		
	}
	
	private KeyPair getKS() throws GeneralSecurityException, IOException
	{
		 
		 Key priv = KS.getKey(alias, pwd.toCharArray());
		 if(priv instanceof PrivateKey)
		 {
			 Certificate cert = KS.getCertificate(alias);
			 PublicKey pub =  cert.getPublicKey();
			 keyPair = new KeyPair(pub, (PrivateKey) priv);
		 }
		 
		 return keyPair;
	}
	
	public String signContent(byte[] content) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		
		final Signature firma = Signature.getInstance("SHA256withRSA");
		firma.initSign(keyPair.getPrivate());
		firma.update(content);
		final byte[] signed = firma.sign();

		return Base64.encodeBase64String(signed);
		
	}
	
	public boolean authenticate(String datagram,String content) throws  GeneralSecurityException 
	{
		final Signature firma = Signature.getInstance("SHA256withRSA");
		firma.initVerify(keyPair.getPublic());
		byte[] ct = Base64.decodeBase64(datagram.getBytes());
		firma.update(content.getBytes());
		if(firma.verify(ct))
		{
			System.out.println("CORRECTO!!!");
			return true;
		}
		else
		{
			System.out.println("INCORRECTO!!! :-( ");
			return false;
		}
		
	}
	
	public String chipher(String text) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

	    byte[] cipherText = encryptCipher.doFinal(text.getBytes("UTF-8"));

	    return Base64.encodeBase64String(cipherText);
		
		
	}
	
	public String dechipher(String encVal) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] bytes = Base64.decodeBase64(encVal);
		Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

	    return new String(decriptCipher.doFinal(bytes), "UTF-8");
	}
	
	public boolean validateCookie(Cookie coo) throws Exception
	{
		DecodedCookie mapa = decodeCookie(coo);
		KeyInfo k = repo.readKeys(mapa.getUser());
		final String chiph = dechipher(k.getChipher());
		
		long mills = (Integer.parseInt(expire))*1000;
		long crea = Long.parseLong(mapa.getCreation());
		
		long res = crea + mills;
		Date d = new Date(res);
		SimpleDateFormat fmt = new SimpleDateFormat("YYYY-MM-DD hh:mm:ss");
		String txtDate = fmt.format(d);
		System.out.println(txtDate);
		
		if(System.currentTimeMillis() < res)
		{
			return authenticate(mapa.getCert(), chiph);
		}
		else
		{
			coo.setMaxAge(0);
			return false;
		}
		
	}
	
	public DecodedCookie decodeCookie(Cookie coo) throws Exception
	{
		
		String raw = coo.getValue();
		String[] s = raw.split("#");
		if(s.length == 3)
		{
			String usu = new String(Base64.decodeBase64(s[0]), "UTF-8");
			DecodedCookie res = new DecodedCookie();
			res.setUser(usu);
			res.setCert(s[1]);
			res.setCreation(s[2]);
			return res;
		}
		else
		{
			throw new BadCredentialsException("Bad Cookie credentials");
		}
	}
}









