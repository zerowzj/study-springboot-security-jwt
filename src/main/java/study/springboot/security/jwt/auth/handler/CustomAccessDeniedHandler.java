package study.springboot.security.jwt.auth.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private String errorPage = "/erro";

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        String ajaxRequest = request.getHeader("X-Requested-With");
        // Set the 403 status code.
//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        if ("XMLHttpRequest".equals(ajaxRequest)) {
            log.info("ssssssssssssssssssss");
        } else {
//            // Put exception into request scope (perhaps of use to a view)
//            request.setAttribute(WebAttributes.ACCESS_DENIED_403, accessDeniedException);
//            // Set the 403 status code.
//            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//            // forward to error page.
//            RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
//            dispatcher.forward(request, response);
//            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter out = response.getWriter();
            out.write("{\"status\":\"error\",\"msg\":\"权限不足，请联系管理员!\"}");
            out.flush();
            out.close();
        }
    }

    public void setErrorPage(String errorPage) {
        if ((errorPage != null) && !errorPage.startsWith("/")) {
            throw new IllegalArgumentException("errorPage must begin with '/'");
        }
        this.errorPage = errorPage;
    }
}
