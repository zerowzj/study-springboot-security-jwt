package study.springboot.security.jwt.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import study.springboot.security.jwt.auth.entrypoint.JwtAuthenticationEntryPoint;
import study.springboot.security.jwt.auth.filter.JwtAuthFilter;
import study.springboot.security.jwt.auth.filter.JwtLoginFilter;

/**
 * SpringSecurity的配置
 * 通过SpringSecurity的配置，将JwtLoginFilter，JwtAuthFilter组合在一起
 */
@Configuration
public class WebSecurityCfg extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true);
        //
        web.ignoring()
                .antMatchers("/demo");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //
        http.csrf().disable();
        //
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //授权
//        http.authorizeRequests()
//                .antMatchers("/demo").permitAll()
//                .anyRequest().authenticated();
        //过滤器
        http.addFilter(new JwtLoginFilter(authenticationManager()))
                .addFilter(new JwtAuthFilter(authenticationManager()));
        //异常处理
        http.exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}