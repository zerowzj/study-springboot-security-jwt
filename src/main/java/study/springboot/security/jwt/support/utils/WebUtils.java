package study.springboot.security.jwt.support.utils;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
public class WebUtils {

    /**
     * ====================
     * 转换Http
     * ====================
     */
    public static HttpServletRequest toHttp(ServletRequest servletRequest) {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        return request;
    }

    public static HttpServletResponse toHttp(HttpServletResponse servletResponse) {
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        return response;
    }

    /**
     * ====================
     * 获取请求头
     * ====================
     */
    public static String getHeader(HttpServletRequest request, String name) {
        return request.getHeader(name);
    }

    /**
     * ====================
     * 发送状态码
     * ====================
     */
    public static void sendError(HttpServletResponse response, int statusCode) {
        sendError(response, statusCode, null);
    }

    public static void sendError(HttpServletResponse response, int statusCode, String msg) {
        try {
            response.sendError(statusCode, msg);
        } catch (Exception ex) {
            log.error("", ex);
        }
    }

    /**
     * ====================
     * 输出信息
     * ====================
     */
    public static void write(HttpServletResponse response, Map<String, Object> result) {
        PrintWriter writer = null;
        try {
            response.setContentType("application/json; charset=UTF-8");
            writer = response.getWriter();
            String text = JsonUtils.toJson(result);
            writer.write(text);
        } catch (Exception ex) {
            log.error("", ex);
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }
}
