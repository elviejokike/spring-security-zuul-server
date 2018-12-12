package com.example.zuul.web;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "auth", ignoreUnknownFields = false)
@Component
public class AuthConfiguration {

	public String grantTypeAuthorization = "Basic ZGVmYXVsdC1jbGllbnQ6c2VjcmV0";

	public String authPath = "/auth";

	public String servicesPath = "/services";
}
