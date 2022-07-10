package com.damiani.authorizationserver.authServer;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.GenericFilterBean;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
//@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.cors(); // uasando o cors definido no webMVC

		return http

				.formLogin(form -> form.loginPage("/login")).build();
	}

	// Caso queira definir configuração do cors sem herdar da definição do webMVC
	@Bean
	public CorsConfigurationSource corsConfigurationSourceCustom() {
		CorsConfiguration config = new CorsConfiguration();
		config.addAllowedOrigin("http://localhost:3000/");
		config.addAllowedHeader("*");
		// config.addAllowedMethod("POST");
		config.setAllowedMethods(Arrays.asList("GET", "POST"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/oauth2/**", config);

		return source;
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://localhost:8080").build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("SGProd")
				.clientSecret("{noop}123456").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientSettings(ClientSettings.builder().requireProofKey(true).build())
				// .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
				.redirectUri("http://10.8.216.99:3000/authorize").scope(OidcScopes.OPENID)

				.build();

		RegisteredClient registeredClient1 = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("rafael")
				.clientSecret("{noop}1234").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://10.8.216.140:8080/auth/test").scope(OidcScopes.OPENID)

				.build();

		RegisteredClient registeredClient3 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("alessandro").clientSecret("{noop}12345")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://www.google.com")
				.scope(OidcScopes.OPENID)

				.build();

		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(16);
		String result = encoder.encode("myPassword");

		RegisteredClient registeredClient2 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("huongdanjava1").clientSecret(result)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).tokenSettings(tokenSettings())
				.scope("accees-hello").build();

//usados no browser para obter authorization code
//com pcke		http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=SGProd&redirect_uri=http://10.8.216.99:3000/authorize&scope=openid&code_challenge=rMKPR6wVdfqySdN2inao89aPtczIzBmXcAGcTJOP0Bk&code_challenge_method=S256&state="STATE"
//sem pkce local		http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=alessandro&redirect_uri=https://www.google.com&scope=openid

		return new InMemoryRegisteredClientRepository(registeredClient, registeredClient1, registeredClient2,
				registeredClient3);

	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);

		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	private static RSAKey generateRsa() throws NoSuchAlgorithmException {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);

		return keyPairGenerator.generateKeyPair();
	}

	@Bean
	public TokenSettings tokenSettings() {
		//@formatter:off
	    return TokenSettings.builder()
	        .accessTokenTimeToLive(Duration.ofMinutes(30L))
	        .build();
	    // @formatter:on
	}

}
