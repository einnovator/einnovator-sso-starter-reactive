/**
 * 
 */
package org.einnovator.sso.client.reactive.config;

import org.einnovator.sso.client.config.SsoClientConfiguration;

/**
 * A {@code ReactiveClientContext} for SSO.
 * 
 * @author support@einnovator.org
 */
public class SsoReactiveClientContext extends ReactiveClientContext {
	
	private SsoClientConfiguration config;

	
	/**
	 * Create instance of {@code SsoContext}.
	 *
	 */
	public SsoReactiveClientContext() {
	}

	/**
	 * Get the value of property {@code config}.
	 *
	 * @return the config
	 */
	public SsoClientConfiguration getConfig() {
		return config;
	}

	/**
	 * Set the value of property {@code config}.
	 *
	 * @param config the value of property config
	 */
	public void setConfig(SsoClientConfiguration config) {
		this.config = config;
	}
	
	//
	// With
	//
	
	/**
	 * Set the value of property {@code config}.
	 *
	 * @param config the value of property config
	 * @return this {@code SsoReactiveClientContext}
	 */
	public SsoReactiveClientContext withConfig(SsoClientConfiguration config) {
		this.config = config;
		return this;
	}
	
}
