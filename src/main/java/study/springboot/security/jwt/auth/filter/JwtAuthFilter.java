package study.springboot.security.jwt.auth.filter;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import study.springboot.security.jwt.auth.Constants;
import study.springboot.security.jwt.support.utils.CookieUtils;
import study.springboot.security.jwt.support.utils.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * token的校验
 * 该类继承自BasicAuthenticationFilter，在doFilterInternal方法中，
 * 从http头的Authorization 项读取token数据，然后用Jwts包提供的方法校验token的合法性。
 * 如果校验通过，就认为这是一个取得授权的合法请求
 */
@Slf4j
@Component
public class JwtAuthFilter extends BasicAuthenticationFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        log.info("======> doFilterInternal");
        //TODO
        String jwt = WebUtils.getHeader(request, Constants.AUTHORIZATION_HEADER);
        if (Strings.isNullOrEmpty(jwt)) {
            throw new BadCredentialsException("需要认证");
        }

//        String jwt = CookieUtils.getValue(request, "jwt");

        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        //
        SecurityContextHolder.getContext()
                .setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        String username = Jwts.parser()
                .setSigningKey("JwtSecret")
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody()
                .getSubject();
        return new UsernamePasswordAuthenticationToken(username, null, Lists.newArrayList());
    }
}
