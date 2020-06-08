package study.springboot.security.jwt.auth.filter;

import com.google.common.collect.Lists;
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
import java.io.InputStream;

@Slf4j
@Component
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info(">>>>>> attemptAuthentication");
        //******************** 获取请求参数 ********************
        InputStream is = null;
        try {
            is = request.getInputStream();
        } catch (Exception ex) {
            log.error("", ex);
        }
        LoginRequest loginRequest = JsonUtils.fromJson(is, LoginRequest.class);

        //******************** 构造Token ********************
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword(),
                Lists.newArrayList());

        //******************** 认证 ********************
        Authentication authentication = authenticationManager.authenticate(token);
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication) throws IOException, ServletException {
        log.info(">>>>>> successfulAuthentication");
        //********************  ********************
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String token = userDetails.getPassword();

        //******************** 生成Cookie ********************
        String jwt = JwtUtils.createJwt(null);
        Cookie cookie = CookieUtils.newCookie("jwt", jwt);
        response.addCookie(cookie);

        WebUtils.write(response, Results.ok());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException ex) throws IOException, ServletException {
        log.info("======> unsuccessfulAuthentication");
    }
}
