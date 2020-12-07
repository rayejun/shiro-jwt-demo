package io.guthub.rayejun.shirojwt.filter;

import io.guthub.rayejun.shirojwt.model.JwtToken;
import io.guthub.rayejun.shirojwt.utils.Constants;
import io.guthub.rayejun.shirojwt.utils.JwtTokenUtil;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        String token = resolveToken(httpServletRequest);
        if (StringUtils.hasText(token)) {
            try {
                JwtTokenUtil.validateToken(token);
                getSubject(request, response).login(new JwtToken(token));
                return true;
            } catch (RuntimeException e) {
                HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
                httpServletResponse.setContentType("application/json; charset=utf-8");
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                try {
                    httpServletResponse.getWriter().write(e.getMessage());
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                return false;
            }
        } else {
            return false;
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
        httpServletResponse.setContentType("application/json; charset=utf-8");
        httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        httpServletResponse.getWriter().write("Forbidden");
        return false;
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        HttpServletRequest req = (HttpServletRequest) request;
        String token = resolveToken(req);
        if (StringUtils.hasText(token)) {
            return isAccessAllowed(request, response, mappedValue);
        } else {
            return onAccessDenied(request, response, mappedValue);
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(Constants.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(Constants.AUTHORIZATION_PREFIX)) {
            return bearerToken.substring(7);
        }
        String token = request.getParameter(Constants.AUTHORIZATION_PARAMETER);
        if (StringUtils.hasText(token)) {
            return token;
        }
        return null;
    }
}
