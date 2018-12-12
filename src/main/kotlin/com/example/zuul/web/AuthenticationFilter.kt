package com.example.zuul.web

import com.example.zuul.web.util.CookieSerializer
import com.example.zuul.web.util.DefaultCookieSerializer
import com.google.gson.Gson
import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.*
import org.springframework.stereotype.Component
import org.springframework.util.StreamUtils
import java.nio.charset.Charset
import javax.servlet.http.HttpServletResponse

/**
 * Acts as an Authentication Proxy between client applications an the OAuth server.
 */
@Component
class AuthenticationFilter: ZuulFilter() {

    override fun shouldFilter(): Boolean {
        var context = RequestContext.getCurrentContext();
        return ("/auth".equals(context.get("requestURI")))
    }

    override fun filterType(): String {
        return PRE_TYPE
    }

    override fun filterOrder(): Int {
        return 999
    }

    override fun run(): Any {

        val context = RequestContext.getCurrentContext()
        context.addZuulRequestHeader("Authorization", "Basic ZGVmYXVsdC1jbGllbnQ6c2VjcmV0");
        context.put(REQUEST_URI_KEY, "/oauth/token");

        return Any()
    }

}

@Component
class PostSuscessfulAuthenticationFilter : ZuulFilter() {

    var gson = Gson()
    var cookieSerializer:CookieSerializer = DefaultCookieSerializer();

    override fun run(): Any {

        val context = RequestContext.getCurrentContext()

        if (context.responseStatusCode == HttpServletResponse.SC_OK) {
            val stream = context.getResponseDataStream()
            val body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"))
            val oauthToken = gson?.fromJson(body, OAuth2AccessToken::class.java)

            context.responseBody = "{}";
            val cookieValue = CookieSerializer.CookieValue(context.request, context.response, oauthToken.access_token);
            cookieValue.cookieMaxAge = oauthToken.expires_in;
            this.cookieSerializer.writeCookieValue(cookieValue);

        }

        return Any()
    }

    override fun shouldFilter(): Boolean {
        var context = RequestContext.getCurrentContext();
        return context.request.requestURI.toString().startsWith  ("/auth")
    }

    override fun filterType(): String {
        return POST_TYPE
    }

    override fun filterOrder(): Int {
        return 1;
    }
}

@Component
class ServiceAuthenticationFilter: ZuulFilter() {

    var cookieSerializer: CookieSerializer = DefaultCookieSerializer();


    override fun shouldFilter(): Boolean {
        var context = RequestContext.getCurrentContext();
        return context.request.requestURI.toString().startsWith  ("/services")
    }

    override fun filterOrder(): Int {
        return 1000
    }

    override fun filterType(): String {
        return PRE_TYPE
    }

    override fun run(): Any {
        val context = RequestContext.getCurrentContext()
        var cookies = cookieSerializer.readCookieValues(context.request)
        if (cookies == null || cookies.size == 0) {
            context.responseStatusCode = 401
            context.sendZuulResponse()
            return Any();
        }
        var auth = cookies.get(0)

        context.addZuulRequestHeader("Authorization", "Bearer " + auth);

        return Any()
    }


}