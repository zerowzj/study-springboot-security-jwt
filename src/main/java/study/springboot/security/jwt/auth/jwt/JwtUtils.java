package study.springboot.security.jwt.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;

import java.util.Map;

public class JwtUtils {

    private final static SignatureAlgorithm DEFAULT_ALGORITHM = SignatureAlgorithm.HS256;

    private final static String DEFAULT_SECRET_KEY = "abc!@#XYZ123";

    public static String createToken(Map<String, Object> claims) {
        return createToken(claims, null, null);
    }

    public static String createToken(Map<String, Object> claims, SignatureAlgorithm algorithm, String base64SecretKey) {
        if (algorithm == null) {
            algorithm = DEFAULT_ALGORITHM;
        }
        if (base64SecretKey == null) {
            base64SecretKey = DEFAULT_SECRET_KEY;
        }
        //payload标准声明和私有声明
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(algorithm, base64SecretKey);
        return builder.compact();
    }

    public static Claims parseToken(String jwt) {
        return parseToken(jwt, null);
    }

    public static Claims parseToken(String jwt, String base64SecretKey) {
        if (base64SecretKey == null) {
            base64SecretKey = DEFAULT_SECRET_KEY;
        }
        Jws<Claims> jws = Jwts.parser()
                .setSigningKey(base64SecretKey)
                .parseClaimsJws(jwt);

        return jws.getBody();
    }

    public boolean verify(String jwt) {

        /*
            // 得到DefaultJwtParser
            Claims claims = decode(jwtToken);

            if (claims.get("password").equals(user.get("password"))) {
                return true;
            }
        */
        return true;
    }

    public static void main(String[] args) {
        Claims claims = new DefaultClaims();
        claims.setId("123123");
        claims.put("username", "tom");
        claims.put("password", "123456");

        String jwtToken = createToken(claims);
        System.out.println(jwtToken);
        /*
        util.isVerify(jwtToken);
        System.out.println("合法");
        */
        parseToken(jwtToken).entrySet().forEach((entry) -> {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        });
    }
}
