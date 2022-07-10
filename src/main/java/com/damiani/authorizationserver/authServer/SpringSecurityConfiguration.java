package com.damiani.authorizationserver.authServer;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
public class SpringSecurityConfiguration {
	
	@Autowired
	private CorsConfigurationSource corsConfigurationSourceCustom;

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		
		//Para configurar a aplicação como Resource server
		http
//		.mvcMatcher("/test/**")
//			.authorizeRequests()
//				.mvcMatchers("/test/**").access("hasAuthority('SCOPE_message.read')")
//				.and()
		.oauth2ResourceServer()
			.jwt();
		
		//Configurar a aplicação para exigir a autenticação
		http
            .authorizeRequests(authorizeRequests ->
                authorizeRequests
                .anyRequest().authenticated()
            )
//            .formLogin(Customizer.withDefaults());
//			Custom login page
            .formLogin(form -> form
    				.loginPage("/login")
    				.permitAll()
    			)
    			.logout(logout -> logout                                                
    		            //.logoutUrl("/logout")
    		            .permitAll()
    		            .logoutSuccessUrl("/login")                                      
    		        )
    			
    			.csrf().disable()
    			.cors()
    			;

		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/webjars/**");
	}

	@Bean
	public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
            .username("admin")
            .password("password")
            .roles("ADMIN").build();

		return new InMemoryUserDetailsManager(user);
	}
}
