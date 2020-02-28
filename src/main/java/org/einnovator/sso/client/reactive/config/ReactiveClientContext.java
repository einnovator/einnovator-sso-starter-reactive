/**
 * 
 */
package org.einnovator.sso.client.reactive.config;

import org.einnovator.util.web.ClientContext;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A reactive {@code ClientContext}.
 * 
 */
public class ReactiveClientContext extends ClientContext {
		
	private WebClient webClient;
	
	/**
	 * Create instance of {@code SsoContext}.
	 *
	 */
	public ReactiveClientContext() {
	}

	/**
	 * Get the value of property {@code webClient}.
	 *
	 * @return the webClient
	 */
	public WebClient getWebClient() {
		return webClient;
	}

	/**
	 * Set the value of property {@code webClient}.
	 *
	 * @param webClient the value of property webClient
	 */
	public void setWebClient(WebClient webClient) {
		this.webClient = webClient;
	}

	//
	// With
	//
	

	/**
	 * Set the value of property {@code webClient}.
	 *
	 * @param webClient the value of property webClient
	 * @return this {@code ReactiveClientContext}
	 */
	public ReactiveClientContext withWebClient(WebClient webClient) {
		this.webClient = webClient;
		return this;
	}

	
}
