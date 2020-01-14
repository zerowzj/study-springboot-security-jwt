package study.springboot.security.jwt.auth.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private static final String DEFAULT_TARGET_URL = "/demo.html";

    private static final boolean ALWAYS_USER_DEFAULT_TARGET_URL = true;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        this.setDefaultTargetUrl(DEFAULT_TARGET_URL);
        this.setAlwaysUseDefaultTargetUrl(ALWAYS_USER_DEFAULT_TARGET_URL);
        LOGGER.info("===>登录成功");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
