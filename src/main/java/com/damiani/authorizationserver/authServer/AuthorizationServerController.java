package com.damiani.authorizationserver.authServer;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class AuthorizationServerController {
    @GetMapping("/login")
    public String viewLoginPage() {
        return "login";
    }
 
    @GetMapping("/")
    public String hello() {
        return "home";
    }
    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }
	@PostMapping("/register")
	public ResponseEntity<?> registerUser(@RequestBody String signUpRequest) {
		return null;
	
	}
}
