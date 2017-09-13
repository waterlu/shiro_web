package cn.lu.learn.shiro.dto;

import cn.zjhf.kingold.common.param.ParamVO;
import org.hibernate.validator.constraints.NotEmpty;

/**
 * Created by lutiehua on 2017/8/29.
 */
public class LoginDTO extends ParamVO {

    /**
     * 登录名
     */
    @NotEmpty(message="用户名称不能为空")
    private String username;

    /**
     * 登录密码
     */
    @NotEmpty(message="密码不能为空")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
