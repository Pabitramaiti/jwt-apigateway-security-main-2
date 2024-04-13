package com.javatechie.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import com.javatechie.util.JwtUtil;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    //    @Autowired
//    private RestTemplate template;
    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        
    	return ((exchange, chain) -> {
        	
        	ServerHttpRequest request = null;
        	
            if (validator.isSecured.test(exchange.getRequest())) {
            	
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }
                
                //Getting token
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7); // authHeader is final token and it contains three fields, (1) HEADER:ALGORITHM & TOKEN TYPE (2) PAYLOAD:DATA and  (3) VERIFY SIGNATURE . Check in jwt.io
                }
                try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
                    jwtUtil.validateToken(authHeader);

                    //Added only for example 4 To extract the username or user information from the token
                    request = exchange.getRequest().mutate().header("loggedInUser", jwtUtil.extractUserName(authHeader)).build();
                    
                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            //return chain.filter(exchange); // for example 3
            return chain.filter(exchange.mutate().request(request).build()); //for example 4
        });
    }

    public static class Config {

    }
}
