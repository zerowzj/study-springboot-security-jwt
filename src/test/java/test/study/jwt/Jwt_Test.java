package test.study.jwt;

import com.google.common.base.Splitter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Date;

@Slf4j
public class Jwt_Test {

    @Test
    public void builder_test() {
        JwtBuilder builder = Jwts.builder();
        //header
        builder.setHeaderParam("typ", "JWT");
        //payload
        builder.setId("123123")
                .setIssuer("123123")
                .setSubject("wzj")
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 1000))
                .setNotBefore(new Date())
                .setIssuedAt(new Date());
        //signature
        builder.signWith(SignatureAlgorithm.HS256, "MyJwtSecret");
        String token = builder.compact();

        Splitter.on(".").splitToList(token).forEach(str -> {
            log.info(str);
            log.info(new String(DatatypeConverter.parseBase64Binary(str)));
        });
        log.info(token);
    }
}
