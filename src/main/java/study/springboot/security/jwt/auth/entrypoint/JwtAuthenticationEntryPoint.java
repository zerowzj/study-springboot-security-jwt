package study.springboot.security.jwt.auth.entrypoint;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.Server;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import study.springboot.security.jwt.support.Results;
import study.springboot.security.jwt.support.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class
JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException, ServletException {
        ServletUtils.write(response, Results.error("9090", "ssss"));
    }
}
