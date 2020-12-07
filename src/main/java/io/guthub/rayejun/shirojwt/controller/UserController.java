package io.guthub.rayejun.shirojwt.controller;

import io.guthub.rayejun.shirojwt.model.User;
import io.guthub.rayejun.shirojwt.utils.Constants;
import io.guthub.rayejun.shirojwt.utils.JwtTokenUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class UserController {

    @RequestMapping("unauthorized")
    public void unauthorized(HttpServletResponse response) {
        response.setContentType("application/json; charset=utf-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        try {
            response.getWriter().write("Unauthorized");
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @RequestMapping("login")
    public Object login(@RequestParam String username, @RequestParam String password, HttpServletResponse response) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        try {
            subject.login(usernamePasswordToken);
            String token = JwtTokenUtil.createToken(username, "1");
            response.addHeader(Constants.AUTHORIZATION_HEADER, Constants.AUTHORIZATION_PREFIX + token);
            return "success token：" + token;
        } catch (UnknownAccountException e) {
            return "登录名不正确！";
        } catch (AuthenticationException e) {
            return "密码不正确！";
        } catch (AuthorizationException e) {
            return "没有权限！";
        }
    }

    @RequestMapping("index")
    public Object index() {
        return "index";
    }

    @RequestMapping("home")
    public Object home() {
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        return user.getUsername();
    }

    @RequiresRoles("ROLE_USER")
    @RequestMapping("user")
    public Object user() {
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        return user.getUsername();
    }

    @RequiresRoles("ROLE_ADMIN")
    @RequestMapping("admin")
    public Object admin() {
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        return user.getUsername();
    }
}
