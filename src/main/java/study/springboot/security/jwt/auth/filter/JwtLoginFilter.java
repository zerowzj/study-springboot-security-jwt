package study.springboot.security.jwt.auth.filter;

import com.google.common.base.Strings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import study.springboot.security.jwt.auth.details.CustomUserDetails;
import study.springboot.security.jwt.auth.jwt.JwtUtils;
import study.springboot.security.jwt.support.result.Results;
import study.springboot.security.jwt.support.utils.CookieUtils;
import study.springboot.security.jwt.support.utils.JsonUtils;
import study.springboot.security.jwt.support.utils.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info(">>>>>> attemptAuthentication");
        //******************** <1>.获取请求参数 ********************
        String body = WebUtils.getBodyText(request);
        LoginRequest loginRequest = JsonUtils.fromJson(body, LoginRequest.class);
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();
        if (Strings.isNullOrEmpty(username)) {
            throw new IllegalArgumentException("");
        }
        if (Strings.isNullOrEmpty(password)) {
            throw new IllegalArgumentException("");
        }
        //******************** <2>.构造Token ********************
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        //******************** <3>.认证并返回 ********************
        Authentication authentication = authenticationManager.authenticate(token);
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication) throws IOException, ServletException {
        log.info(">>>>>> successfulAuthentication");
        //******************** <1>. ********************
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String token = userDetails.getPassword();

        //******************** <2>.生成Cookie ********************
        String jwt = JwtUtils.createJwt(null);
        Cookie cookie = CookieUtils.newCookie("jwt", jwt);
        response.addCookie(cookie);

        //******************** <3>. ********************
        WebUtils.write(response, Results.ok());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException ex) throws IOException, ServletException {
        log.info(">>>>>> unsuccessfulAuthentication");
    }
}
