package study.springboot.security.jwt.auth.filter;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoginRequest {

    private String username;

    private String password;
}
