package study.springboot.security.jwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import study.springboot.security.jwt.support.result.Results;

import java.util.Map;

@Slf4j
@RestController
public class DemoController {

    @GetMapping("/demo")
    public Map<String, Object> demo() {
        log.info("执行/demo");
        return Results.ok();
    }
}
