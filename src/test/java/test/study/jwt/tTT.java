package test.study.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.util.Date;

@Slf4j
public class tTT {

    @Test
    public void token_test(){
        String token = Jwts.builder()
                .setSubject("wzj")
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 1000))
                .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")
                .compact();
        String user = Jwts.parser()
                .setSigningKey("MyJwtSecret")
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        log.info(token);
        log.info(user);
    }
}
