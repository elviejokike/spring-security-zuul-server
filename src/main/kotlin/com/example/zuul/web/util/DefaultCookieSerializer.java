package com.example.zuul.web.util;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.BitSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DefaultCookieSerializer implements CookieSerializer {

	private static final BitSet domainValid = new BitSet(128);

	static {
		for (char c = '0'; c <= '9'; c++) {
			domainValid.set(c);
		}
		for (char c = 'a'; c <= 'z'; c++) {
			domainValid.set(c);
		}
		for (char c = 'A'; c <= 'Z'; c++) {
			domainValid.set(c);
		}
		domainValid.set('.');
		domainValid.set('-');
	}

	private String cookieName = "SID";

	private Boolean useSecureCookie;

	private boolean useHttpOnlyCookie = true;

	private String cookiePath;

	private Integer cookieMaxAge;

	private String domainName;

	private Pattern domainNamePattern;

	private String jvmRoute;

	private boolean useBase64Encoding = false;

	private String rememberMeRequestAttribute;

	private String sameSite = "Lax";

	@Override
	public List<String> readCookieValues(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		List<String> matchingCookieValues = new ArrayList<>();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (this.cookieName.equals(cookie.getName())) {
					String sessionId = (this.useBase64Encoding
							? base64Decode(cookie.getValue())
							: cookie.getValue());
					if (sessionId == null) {
						continue;
					}
					if (this.jvmRoute != null && sessionId.endsWith(this.jvmRoute)) {
						sessionId = sessionId.substring(0,
								sessionId.length() - this.jvmRoute.length());
					}
					matchingCookieValues.add(sessionId);
				}
			}
		}
		return matchingCookieValues;
	}

	@Override
	public void writeCookieValue(CookieValue cookieValue) {
		HttpServletRequest request = cookieValue.getRequest();
		HttpServletResponse response = cookieValue.getResponse();

		StringBuilder sb = new StringBuilder();
		sb.append(this.cookieName).append('=');
		String value = getValue(cookieValue);
		if (value != null && value.length() > 0) {
			validateValue(value);
			sb.append(value);
		}
		int maxAge = getMaxAge(cookieValue);
		if (maxAge > -1) {
			sb.append("; Max-Age=").append(cookieValue.getCookieMaxAge());
			OffsetDateTime expires = (maxAge != 0)
					? OffsetDateTime.now().plusSeconds(maxAge)
					: Instant.EPOCH.atOffset(ZoneOffset.UTC);
			sb.append("; Expires=")
					.append(expires.format(DateTimeFormatter.RFC_1123_DATE_TIME));
		}
		String domain = getDomainName(request);
		if (domain != null && domain.length() > 0) {
			validateDomain(domain);
			sb.append("; Domain=").append(domain);
		}
		String path = getCookiePath(request);
		if (path != null && path.length() > 0) {
			validatePath(path);
			sb.append("; Path=").append(path);
		}
		if (isSecureCookie(request)) {
			sb.append("; Secure");
		}
		if (this.useHttpOnlyCookie) {
			sb.append("; HttpOnly");
		}
		if (this.sameSite != null) {
			sb.append("; SameSite=").append(this.sameSite);
		}

		response.addHeader("Set-Cookie", sb.toString());
	}

	private String base64Decode(String base64Value) {
		try {
			byte[] decodedCookieBytes = Base64.getDecoder().decode(base64Value);
			return new String(decodedCookieBytes);
		}
		catch (Exception ex) {
			return null;
		}
	}

	private String base64Encode(String value) {
		byte[] encodedCookieBytes = Base64.getEncoder().encode(value.getBytes());
		return new String(encodedCookieBytes);
	}

	private String getValue(CookieValue cookieValue) {
		String requestedCookieValue = cookieValue.getCookieValue();
		String actualCookieValue = requestedCookieValue;
		if (this.jvmRoute != null) {
			actualCookieValue = requestedCookieValue + this.jvmRoute;
		}
		if (this.useBase64Encoding) {
			actualCookieValue = base64Encode(actualCookieValue);
		}
		return actualCookieValue;
	}

	private void validateValue(String value) {
		int start = 0;
		int end = value.length();
		if ((end > 1) && (value.charAt(0) == '"') && (value.charAt(end - 1) == '"')) {
			start = 1;
			end--;
		}
		char[] chars = value.toCharArray();
		for (int i = start; i < end; i++) {
			char c = chars[i];
			if (c < 0x21 || c == 0x22 || c == 0x2c || c == 0x3b || c == 0x5c
					|| c == 0x7f) {
				throw new IllegalArgumentException(
						"Invalid character in cookie value: " + Integer.toString(c));
			}
		}
	}

	private int getMaxAge(CookieValue cookieValue) {
		int maxAge = cookieValue.getCookieMaxAge();
		if (maxAge < 0) {
			if (this.rememberMeRequestAttribute != null && cookieValue.getRequest()
					.getAttribute(this.rememberMeRequestAttribute) != null) {
				// the cookie is only written at time of session creation, so we rely on
				// session expiration rather than cookie expiration if remember me is
				// enabled
				cookieValue.setCookieMaxAge(Integer.MAX_VALUE);
			}
			else if (this.cookieMaxAge != null) {
				cookieValue.setCookieMaxAge(this.cookieMaxAge);
			}
		}
		return cookieValue.getCookieMaxAge();
	}

	private void validateDomain(String domain) {
		int i = 0;
		int cur = -1;
		int prev;
		char[] chars = domain.toCharArray();
		while (i < chars.length) {
			prev = cur;
			cur = chars[i];
			if (!domainValid.get(cur)
					|| ((prev == '.' || prev == -1) && (cur == '.' || cur == '-'))
					|| (prev == '-' && cur == '.')) {
				throw new IllegalArgumentException("Invalid cookie domain: " + domain);
			}
			i++;
		}
		if (cur == '.' || cur == '-') {
			throw new IllegalArgumentException("Invalid cookie domain: " + domain);
		}
	}

	private void validatePath(String path) {
		for (char ch : path.toCharArray()) {
			if (ch < 0x20 || ch > 0x7E || ch == ';') {
				throw new IllegalArgumentException("Invalid cookie path: " + path);
			}
		}
	}

	public void setUseSecureCookie(boolean useSecureCookie) {
		this.useSecureCookie = useSecureCookie;
	}

	public void setUseHttpOnlyCookie(boolean useHttpOnlyCookie) {
		this.useHttpOnlyCookie = useHttpOnlyCookie;
	}

	private boolean isSecureCookie(HttpServletRequest request) {
		if (this.useSecureCookie == null) {
			return request.isSecure();
		}
		return this.useSecureCookie;
	}

	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}

	public void setCookieName(String cookieName) {
		if (cookieName == null) {
			throw new IllegalArgumentException("cookieName cannot be null");
		}
		this.cookieName = cookieName;
	}


	public void setCookieMaxAge(int cookieMaxAge) {
		this.cookieMaxAge = cookieMaxAge;
	}

	public void setDomainName(String domainName) {
		if (this.domainNamePattern != null) {
			throw new IllegalStateException(
					"Cannot set both domainName and domainNamePattern");
		}
		this.domainName = domainName;
	}

	public void setDomainNamePattern(String domainNamePattern) {
		if (this.domainName != null) {
			throw new IllegalStateException(
					"Cannot set both domainName and domainNamePattern");
		}
		this.domainNamePattern = Pattern.compile(domainNamePattern,
				Pattern.CASE_INSENSITIVE);
	}

	public void setJvmRoute(String jvmRoute) {
		this.jvmRoute = "." + jvmRoute;
	}

	public void setUseBase64Encoding(boolean useBase64Encoding) {
		this.useBase64Encoding = useBase64Encoding;
	}


	public void setRememberMeRequestAttribute(String rememberMeRequestAttribute) {
		if (rememberMeRequestAttribute == null) {
			throw new IllegalArgumentException(
					"rememberMeRequestAttribute cannot be null");
		}
		this.rememberMeRequestAttribute = rememberMeRequestAttribute;
	}

	public void setSameSite(String sameSite) {
		this.sameSite = sameSite;
	}

	private String getDomainName(HttpServletRequest request) {
		if (this.domainName != null) {
			return this.domainName;
		}
		if (this.domainNamePattern != null) {
			Matcher matcher = this.domainNamePattern.matcher(request.getServerName());
			if (matcher.matches()) {
				return matcher.group(1);
			}
		}
		return null;
	}

	private String getCookiePath(HttpServletRequest request) {
		if (this.cookiePath == null) {
			return request.getContextPath() + "/";
		}
		return this.cookiePath;
	}

}
