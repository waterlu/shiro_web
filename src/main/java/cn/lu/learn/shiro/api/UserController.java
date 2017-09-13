package cn.lu.learn.shiro.api;

import cn.lu.learn.shiro.constant.ErrorMessage;
import cn.lu.learn.shiro.dto.LoginDTO;
import cn.lu.learn.shiro.vo.UserVO;
import cn.zjhf.kingold.common.constant.ResponseCode;
import cn.zjhf.kingold.common.exception.BusinessException;
import cn.zjhf.kingold.common.result.ResponseResult;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

/**
 * Created by lutiehua on 2017/9/13.
 */
@RestController
@RequestMapping("/api/users")
@CrossOrigin
public class UserController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 用户登录
     *
     * @return
     * @throws BusinessException
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseResult login(LoginDTO param) throws BusinessException {
        ResponseResult responseResult = new ResponseResult();

        String username = param.getUsername();
        String password = param.getPassword();

        if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            responseResult.setCode(ResponseCode.PARAM_ERROR);
            responseResult.setMsg(ResponseCode.PARAM_ERROR_TEXT);
            return responseResult;
        }

        UsernamePasswordToken token = new UsernamePasswordToken(username, password, false);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
            responseResult.setCode(ResponseCode.OK);
            responseResult.setMsg(ResponseCode.OK_TEXT);
        }catch(UnknownAccountException uae){
            logger.error("对用户[" + username + "]进行登录验证..验证未通过,未知账户");
            responseResult.setCode(ErrorMessage.UNKNOWN_USER);
            responseResult.setMsg(ErrorMessage.UNKNOWN_USER_TXT);
        }catch(IncorrectCredentialsException ice){
            logger.error("对用户[" + username + "]进行登录验证..验证未通过,错误的凭证");
            responseResult.setCode(ErrorMessage.INCORRECT_CREDENTIAL);
            responseResult.setMsg(ErrorMessage.INCORRECT_CREDENTIAL_TXT);
        }catch(LockedAccountException lae){
            logger.error("对用户[" + username + "]进行登录验证..验证未通过,账户已锁定");
            responseResult.setCode(ErrorMessage.LOCKED_ACCOUNT);
            responseResult.setMsg(ErrorMessage.LOCKED_ACCOUNT_TXT);
        }catch(ExcessiveAttemptsException eae){
            logger.error("对用户[" + username + "]进行登录验证..验证未通过,错误次数过多");
            responseResult.setCode(ErrorMessage.EXCESSIVE_ATTEMPT);
            responseResult.setMsg(ErrorMessage.EXCESSIVE_ATTEMPT_TXT);
        }catch(AuthenticationException ae){
            logger.error("对用户[" + username + "]进行登录验证..验证未通过,堆栈轨迹如下");
            ae.printStackTrace();
            responseResult.setCode(ErrorMessage.AUTHENTICATE_EXCEPTION);
            responseResult.setMsg(ErrorMessage.AUTHENTICATE_EXCEPTION_TXT);
        }

        token.clear();
        return responseResult;
    }

    /**
     * 用户未登录的统一错误返回
     *
     * @return
     */
    @RequestMapping(value="/login", method=RequestMethod.GET)
    public ResponseResult loginPrompt(){
        ResponseResult responseResult = new ResponseResult();
        responseResult.setCode(ErrorMessage.UNAUTHORIZED_USER);
        responseResult.setMsg(ErrorMessage.UNAUTHORIZED_USER_TXT);
        return responseResult;
    }

    /**
     * 用户登出
     *
     * @return
     * @throws BusinessException
     */
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseResult logout(String traceID) throws BusinessException {
        ResponseResult responseResult = new ResponseResult();
        SecurityUtils.getSubject().logout();
        responseResult.setCode(ResponseCode.OK);
        responseResult.setMsg(ResponseCode.OK_TEXT);
        if (StringUtils.isNotBlank(traceID)) {
            responseResult.setTraceID(traceID);
        }
        return responseResult;
    }

    /**
     * 获取当前用户信息
     *
     * @return
     * @throws BusinessException
     */
    @RequestMapping(value = "/me", method = RequestMethod.GET)
    public ResponseResult currentUser(@RequestParam(required = false) String traceID) throws BusinessException {
        ResponseResult responseResult = new ResponseResult();
        Session session = SecurityUtils.getSubject().getSession(false);
        logger.info("sessionId={}", session.getId().toString());
        UserVO userInfo = (UserVO) SecurityUtils.getSubject().getPrincipals().getPrimaryPrincipal();
        responseResult.setCode(ResponseCode.OK);
        responseResult.setMsg(ResponseCode.OK_TEXT);
        responseResult.setData(userInfo);
        if (StringUtils.isNotBlank(traceID)) {
            responseResult.setTraceID(traceID);
        }
        return responseResult;
    }

}

