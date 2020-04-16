package com.codelovin.springsecurity.passwordstoragedemo;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

@SpringBootApplication
public class PasswordStorageDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(PasswordStorageDemoApplication.class, args);
		
		checkBCryptedPassword();
	}

	private static void checkBCryptedPassword() {
		System.out.println("\n\n");
		
		// DelegatingPasswordEncoder >> A password encoder that delegates to another 
		// PasswordEncoder based upon a prefixed identifier.
		
		
		// Creating Default DelegatingPasswordEncoder
		PasswordEncoder passwordEncoder =
			    PasswordEncoderFactories.createDelegatingPasswordEncoder();
		
		String rawPwd = "pWd$1234";
		String encodedPwd = passwordEncoder.encode(rawPwd);
		
		// You will see output of below format:
		//
		//		{id}encodedPassword
		//
		// If password is encoded with adaptive one-way function "bcrypt", then the format will
		// be as follows:
		//
		//		{bcrypt}encodedPassword
		//
		System.out.println(encodedPwd);
		
		// Creating Custom DelegatingPasswordEncoder
		passwordEncoder = getCustomDelegatingPasswordEncoder();
		encodedPwd = passwordEncoder.encode(rawPwd);
		System.out.println(encodedPwd);
		
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12); // Strength set as 12
		encodedPwd = encoder.encode(rawPwd);
		System.out.println("{bcrypt}" + encodedPwd);
		
		// About Brypted password:
		//
		// 		{bcrypt}$2a$12$kL.xOsD.70qKj8Nfw6r0RejUOjatlGObIz07dvCbJ2TRsiDNn9BrK
		// 
		// 		$2a$  12$   kL.xOsD.70qKj8Nfw6r0Re   jUOjatlGObIz07dvCbJ2TRsiDNn9BrK
		//
		//		$2a$ ==> represents version of BCrypt
		//		12$  ==> represents the cost factor representing number of iterations of the key derivation
		//		kL.xOsD.70qKj8Nfw6r0Re ==> 22 characters are the salt of the password
		//		jUOjatlGObIz07dvCbJ2TRsiDNn9BrK ==> 31 characters represent the hashed password itself		
	}
	
	private static PasswordEncoder getCustomDelegatingPasswordEncoder() {
		 
		String idForEncode = "bcrypt";
		
		Map<String, PasswordEncoder> encoders = new HashMap<>();
		encoders.put(idForEncode, new BCryptPasswordEncoder());
		encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
		encoders.put("scrypt", new SCryptPasswordEncoder());

		// idForEncode is used to lookup which PasswordEncoder should be used for encode
		PasswordEncoder passwordEncoder =
		    new DelegatingPasswordEncoder(idForEncode, encoders);
		
		return passwordEncoder;
	}

}
