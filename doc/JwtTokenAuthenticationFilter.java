package study.springboot.security.jwt.auth.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final String TOKEN_HEADER = "TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(this.TOKEN_HEADER);
        final String auth_token_start = "Bearer ";
        if (Strings.isNotEmpty(token) && token.startsWith(auth_token_start)) {
            token = token.substring(auth_token_start.length());
        } else {
            // 不按规范,不允许通过验证
            token = null;
        }
        String username = jwtUtils.getUsernameFromToken(auth_token);
        logger.info(String.format("Checking authentication for user %s.", username));
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = jwtUtils.getUserFromToken(auth_token);
            if (jwtUtils.validateToken(auth_token, user)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info(String.format("Authenticated user %s, setting security context", username));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
