package com.example.zuul.web.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public interface CookieSerializer {

	void writeCookieValue(CookieValue cookieValue);

	List<String> readCookieValues(HttpServletRequest request);

	class CookieValue {

		private final HttpServletRequest request;

		private final HttpServletResponse response;

		private final String cookieValue;

		private int cookieMaxAge = -1;

		public CookieValue(HttpServletRequest request, HttpServletResponse response,
						   String cookieValue) {
			this.request = request;
			this.response = response;
			this.cookieValue = cookieValue;
			if ("".equals(this.cookieValue)) {
				this.cookieMaxAge = 0;
			}
		}

		/**
		 * Gets the request to use.
		 * @return the request to use. Cannot be null.
		 */
		public HttpServletRequest getRequest() {
			return this.request;
		}

		/**
		 * Gets the response to write to.
		 * @return the response to write to. Cannot be null.
		 */
		public HttpServletResponse getResponse() {
			return this.response;
		}

		/**
		 * The value to be written. This value may be modified by the
		 * {@link CookieSerializer} before written to the cookie. However, the value must
		 * be the same as the original when it is read back in.
		 *
		 * @return the value to be written
		 */
		public String getCookieValue() {
			return this.cookieValue;
		}

		/**
		 * Get the cookie max age. The default is -1 which signals to delete the cookie
		 * when the browser is closed, or 0 if cookie value is empty.
		 * @return the cookie max age
		 */
		public int getCookieMaxAge() {
			return this.cookieMaxAge;
		}

		/**
		 * Set the cookie max age.
		 * @param cookieMaxAge the cookie max age
		 */
		public void setCookieMaxAge(int cookieMaxAge) {
			this.cookieMaxAge = cookieMaxAge;
		}
	}


}
