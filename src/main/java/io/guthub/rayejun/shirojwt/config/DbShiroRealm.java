package io.guthub.rayejun.shirojwt.config;

import io.guthub.rayejun.shirojwt.model.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class DbShiroRealm extends AuthorizingRealm {

    public DbShiroRealm() {
        this.setCredentialsMatcher(new HashedCredentialsMatcher(Md5Hash.ALGORITHM_NAME));
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null) {
            throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
        }

        return new SimpleAuthorizationInfo();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken userToken = (UsernamePasswordToken) token;
        String username = userToken.getUsername();
        if (username == null || username.equals("")) {
            throw new UnknownAccountException(username + " not found");
        }
//        if (user == null) {
//            throw new UnknownAccountException(username + " not found");
//        }
        User user = new User();
        user.setUsername(username);
        user.setPassword("96e79218965eb72c92a549dd5a330112");
        //查询用户的角色和权限存到SimpleAuthenticationInfo中，这样在其它地方
        //SecurityUtils.getSubject().getPrincipal()就能拿出用户的所有信息，包括角色和权限
        return new SimpleAuthenticationInfo(user, user.getPassword(), user.getUsername());
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }
}
