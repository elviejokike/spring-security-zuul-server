package com.example.zuul.web

import com.google.gson.Gson
import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext
import org.springframework.beans.factory.annotation.Autowired
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

    var gson = Gson();

    @Autowired
    lateinit  var sessionHandler:SessionHandler;

    override fun run(): Any {

        val context = RequestContext.getCurrentContext()

        if (context.responseStatusCode == HttpServletResponse.SC_OK) {
            val stream = context.getResponseDataStream()
            val body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"))
            val oauthToken = gson?.fromJson(body, OAuth2AccessToken::class.java)

            this.sessionHandler.handleSusccesfullAuthentication(context.request, context.response, oauthToken);
            context.responseBody = "{}";
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
    @Autowired
    lateinit  var sessionHandler:SessionHandler;

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
        try {
            val accessToken = sessionHandler.handleRequest(context.request, context.response)
            context.addZuulRequestHeader("Authorization", "Bearer $accessToken");
        } catch (e:InvalidSession){
            context.responseStatusCode = 401
            context.sendZuulResponse()
        }
        return Any();
    }
}

class InvalidSession : Throwable() {

}
