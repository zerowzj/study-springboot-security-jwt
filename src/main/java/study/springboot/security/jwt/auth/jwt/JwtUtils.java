package study.springboot.security.jwt.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Map;

public class JwtUtils {

    private final static SignAlg DEFAULT_ALGORITHM = SignAlg.HS256;

    private final static String DEFAULT_SECRET_KEY = "abc!@#XYZ123";

    /**
     * ====================
     * 生成jwt
     * ====================
     */
    public static String createJwt(Map<String, Object> claims) {
        return createJwt(claims, null, null);
    }

    public static String createJwt(Map<String, Object> claims, SignAlg signAlg, String secretKey) {
        SignatureAlgorithm algorithm = transform(signAlg);
        if(secretKey == null){
            secretKey = DEFAULT_SECRET_KEY;
        }
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(algorithm, secretKey);
        String jwt = builder.compact();
        return jwt;
    }

    /**
     * ====================
     * 验证jwt
     * ====================
     */
    public boolean verify(String jwt, SignAlg signAlg, String secretKey) {
        SignatureAlgorithm algorithm = transform(signAlg);
        if(secretKey == null){
            secretKey = DEFAULT_SECRET_KEY;
        }
        return true;
    }

    /**
     * ====================
     * 解析jwt
     * ====================
     */
    public static Claims parseJwt(String jwt) {
        Jws<Claims> jws = Jwts.parser()
                .parseClaimsJws(jwt);
        return jws.getBody();
    }

    private static SignatureAlgorithm transform(SignAlg signAlg) {
        if (signAlg == null) {
            signAlg = DEFAULT_ALGORITHM;
        }
        SignatureAlgorithm algorithm;
        switch (signAlg) {
            case HS256:
                algorithm = SignatureAlgorithm.HS256;
                break;
            case HS512:
                algorithm = SignatureAlgorithm.HS512;
                break;
            default:
                throw new RuntimeException("不支持的算法");
        }
        return algorithm;
    }
}
