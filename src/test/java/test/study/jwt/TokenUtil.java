package test.study.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Slf4j
public class TokenUtil {

    private final static String myApiKeySecret = "这里写入你的Secret";

    /**
     * 创建JSON WEB TOKEN
     * @param id
     * @param userName
     * @param userPower
     * @param ttlMillis
     * @return
     */
    public static String createJWT(String id, String userName, String userPower, long ttlMillis){

        //设置签名算法
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        //设置密钥
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(myApiKeySecret);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        //设置JWT claims
            JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
                .setId(id)
                .setIssuedAt(now)
                .setAudience("iot")
                .setIssuer("Jerry")  //设置发行者，自定义
                .claim("userName", userName)
                .claim("userPower", userPower)
                .signWith(signatureAlgorithm, signingKey);

        //设置超时时间
        if (ttlMillis >= 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //生成JWT
        return builder.compact();

    }

    /**
     * 解析JWT，并验证用户权限
     * @param jwt
     */
    public static Boolean parseJWT(String jwt) throws ParseException {

        if (jwt == null) {
            log.error("----------Token不能为空------------");
            return false;
        }
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(DatatypeConverter.parseBase64Binary(myApiKeySecret))
                    .parseClaimsJws(jwt).getBody();

            //将超时时间格式化为时间戳time
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            String timeFormat = sdf.format(claims.getExpiration());

            Date date = sdf.parse(timeFormat);
            long time = date.getTime();
            long currentTime = System.currentTimeMillis();


            return ("Jerry").equals(claims.getIssuer()) &&
                    ("iot").equals(claims.getAudience()) &&
                    (time > currentTime) &&
                    claims.get("userName") != null;

        }catch (Exception e){
            e.printStackTrace();
            log.error("----------Token格式有误------------");
            return false;
        }
    }

    /**
     * 获取jwt中的userName
     * @param jwt
     * @return
     */
    public static String getUserName(String jwt){

        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(myApiKeySecret))
                .parseClaimsJws(jwt).getBody();

        return claims.get("userName").toString();
    }

}
