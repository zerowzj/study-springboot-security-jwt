package study.springboot.security.jwt.support.utils;

import com.alibaba.fastjson.JSON;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;

@Slf4j
public class JsonUtils {

    public static <T> T fromJson(InputStream is, Class<T> clazz) {
        T obj = null;
        try {
            obj = JSON.parseObject(is, clazz);
        } catch (Exception ex) {
            log.error("", ex);
        }
        return obj;
    }
}
