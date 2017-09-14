package cn.lu.learn.shiro.security;

import cn.lu.learn.shiro.vo.UserVO;
import com.alibaba.fastjson.JSON;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import javax.annotation.Resource;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

/**
 * Created by lutiehua on 2017/9/13.
 */
public class RedisSessionDAO extends EnterpriseCacheSessionDAO {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    // session 在redis过期时间是30分钟30*60
    private static int expireTime = 30*60*1000;

    private static String prefix = "shiro-session:";

    @Resource(name = "redisTemplate")
    private RedisTemplate redisTemplate;

    @Resource(name = "redisStringTemplate")
    private RedisTemplate<String, String> redisStringTemplate;

    // 创建session
    @Override
    protected Serializable doCreate(Session session) {
        Serializable sessionId = super.doCreate(session);
        logger.debug("创建session:{}", session.getId());
        ValueOperations<String, Object> valueOperations = redisTemplate.opsForValue();
        valueOperations.set(prefix + sessionId.toString(), session);
        return sessionId;
    }

    // 获取session
    @Override
    protected Session doReadSession(Serializable sessionId) {
        logger.debug("获取session:{}", sessionId);
        // 先从缓存中获取session，如果没有再去数据库中获取
        Session session = super.doReadSession(sessionId);
        if (session == null) {
            ValueOperations<String, Object> valueOperations = redisTemplate.opsForValue();
            session = (Session) valueOperations.get(prefix + sessionId.toString());

            HashOperations<String, String, String> hashOperations = redisStringTemplate.opsForHash();
            String jsonString = hashOperations.get(prefix, session.getId().toString());
            if (null != jsonString) {
                UserVO user = JSON.parseObject(jsonString, UserVO.class);
                SimplePrincipalCollection pc = new SimplePrincipalCollection();
                pc.add(user, "RedisSessionDAO");
                session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, pc);

//                Subject subject = ThreadContext.getSubject();
//                if (null != subject) {
//                    subject.runAs(pc);
//                }
            }
        }
        return session;
    }

    // 更新session的最后一次访问时间
    @Override
    protected void doUpdate(Session session) {
        super.doUpdate(session);

        String sessionId = session.getId().toString();
        logger.debug("获取session:{}", sessionId);

        PrincipalCollection pc = (PrincipalCollection)session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
        if (null != pc) {
            HashOperations<String, String, String> hashOperations = redisStringTemplate.opsForHash();
            UserVO user = (UserVO) pc.getPrimaryPrincipal();
            String jsonString = JSON.toJSONString(user);
            hashOperations.put(prefix, session.getId().toString(), jsonString);
        }

        String key = prefix + session.getId().toString();
        if (!redisTemplate.hasKey(key)) {
            ValueOperations<String, Object> valueOperations = redisTemplate.opsForValue();
            valueOperations.set(key, session);
        }
        redisTemplate.expire(key, expireTime, TimeUnit.SECONDS);
    }

    // 删除session
    @Override
    protected void doDelete(Session session) {
        logger.debug("删除session:{}", session.getId());
        super.doDelete(session);
        redisTemplate.delete(prefix + session.getId().toString());
        HashOperations<String, String, String> hashOperations = redisTemplate.opsForHash();
        hashOperations.delete(prefix, session.getId().toString());
    }
}