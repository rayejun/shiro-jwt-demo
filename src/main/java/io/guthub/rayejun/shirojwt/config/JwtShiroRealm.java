package io.guthub.rayejun.shirojwt.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.guthub.rayejun.shirojwt.model.JwtToken;
import io.guthub.rayejun.shirojwt.model.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.text.ParseException;

public class JwtShiroRealm extends AuthorizingRealm {

    public JwtShiroRealm() {
        this.setCredentialsMatcher(new JwtCredentialsMatcher());
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null) {
            throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
        }

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.addRole("ROLE_USER");
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        try {
            SignedJWT jwt = SignedJWT.parse((String) token.getPrincipal());
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String username = claims.getSubject();
            User user = new User();
            user.setUsername(username);
            return new SimpleAuthenticationInfo(user, token.getCredentials(), user.getUsername());
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }
}
