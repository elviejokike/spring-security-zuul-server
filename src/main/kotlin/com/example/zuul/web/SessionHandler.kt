package com.example.zuul.web

import com.example.zuul.web.util.CookieSerializer
import com.example.zuul.web.util.DefaultCookieSerializer
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

interface SessionHandler {

    fun handleSusccesfullAuthentication(request: HttpServletRequest, response: HttpServletResponse, oauthToken: OAuth2AccessToken);
    fun handleUnSusccesfullAuthentication(request: HttpServletRequest, response: HttpServletResponse);
    fun handleRequest(request: HttpServletRequest, response: HttpServletResponse): String;

}
@Component
class CookieBasedSessionHandler: SessionHandler {

    var hpCookieSerializer: DefaultCookieSerializer = DefaultCookieSerializer("SHPID", false, false)
    var sigCookieSerializer: DefaultCookieSerializer = DefaultCookieSerializer("SSIGID", true, false);

    override fun handleSusccesfullAuthentication(request: HttpServletRequest, response: HttpServletResponse, oauthToken: OAuth2AccessToken){

        var jwtParts = oauthToken.access_token.split(".");

        val hpCookieValue = CookieSerializer.CookieValue(request, response, jwtParts[0] + "." + jwtParts[1]);
        hpCookieValue.cookieMaxAge = oauthToken.expires_in;
        hpCookieSerializer.writeCookieValue(hpCookieValue);

        val sigCookieValue = CookieSerializer.CookieValue(request, response, jwtParts[2]);
        sigCookieValue.cookieMaxAge = oauthToken.expires_in;
        sigCookieSerializer.writeCookieValue(sigCookieValue);
    }

    override fun handleUnSusccesfullAuthentication(request: HttpServletRequest, response: HttpServletResponse){

    }

    override fun handleRequest(request: HttpServletRequest, response: HttpServletResponse): String{
        var hpCookie = this.hpCookieSerializer.readCookieValues(request)
        var sigCookie = this.sigCookieSerializer.readCookieValues(request)
        if (hpCookie == null || hpCookie.size == 0 || sigCookie == null || sigCookie.size == 0) {
            throw InvalidSession()
        }

        return hpCookie[0] + "." + sigCookie[0];
    }

}
