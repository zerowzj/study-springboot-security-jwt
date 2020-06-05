package study.springboot.security.jwt.support.utils;

import javax.servlet.http.Cookie;

public final class CookieUtils {

    private static final Integer DEFAULT_EXPIRY = 1 * 60;

    private CookieUtils() {
    }

    public static Cookie newCookie(String name, String value) {
        return newCookie(name, value, DEFAULT_EXPIRY);
    }

    public static Cookie newCookie(String name, String value, int expiry) {
        return newCookie(name, value, expiry, true);
    }

    public static Cookie newCookie(String name, String value,
                                   int expiry, boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(expiry);
        return cookie;
    }
}
