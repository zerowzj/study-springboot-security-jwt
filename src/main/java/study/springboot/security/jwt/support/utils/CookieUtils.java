package study.springboot.security.jwt.support.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public final class CookieUtils {

    private static final Integer DEFAULT_EXPIRY = 1 * 60;

    private CookieUtils() {
    }

    /**
     * ====================
     * 创建Cookie
     * ====================
     */
    public static Cookie newCookie(String name, String value) {
        return newCookie(name, value, DEFAULT_EXPIRY);
    }

    public static Cookie newCookie(String name, String value, int expiry) {
        return newCookie(name, value, expiry, true);
    }

    public static Cookie newCookie(String name, String value, int expiry, boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(expiry);
        return cookie;
    }

    /**
     * ====================
     * 获取Cookie值
     * ====================
     */
    public static String getValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        String value = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String n = cookie.getName();
                if (name.equalsIgnoreCase(n)) {
                    value = cookie.getValue();
                    break;
                }
                cookie.getName();
            }
        }
        return value;
    }
}
