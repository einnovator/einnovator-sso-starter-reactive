package org.einnovator.sso.client.reactive;

import static org.einnovator.sso.client.SsoClient.isAdminRequest;
import static org.einnovator.sso.client.SsoClient.processURI;
import static org.einnovator.util.UriUtils.encode;
import static org.einnovator.util.UriUtils.encodeId;
import static org.einnovator.util.UriUtils.makeURI;

import java.net.URI;
import java.security.Principal;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.einnovator.sso.client.SsoClient;
import org.einnovator.sso.client.config.SsoClientConfiguration;
import org.einnovator.sso.client.config.SsoEndpoints;
import org.einnovator.sso.client.model.Client;
import org.einnovator.sso.client.model.Group;
import org.einnovator.sso.client.model.Invitation;
import org.einnovator.sso.client.model.InvitationStats;
import org.einnovator.sso.client.model.Member;
import org.einnovator.sso.client.model.Role;
import org.einnovator.sso.client.model.SsoRegistration;
import org.einnovator.sso.client.model.User;
import org.einnovator.sso.client.modelx.ClientFilter;
import org.einnovator.sso.client.modelx.ClientOptions;
import org.einnovator.sso.client.modelx.GroupFilter;
import org.einnovator.sso.client.modelx.InvitationFilter;
import org.einnovator.sso.client.modelx.InvitationOptions;
import org.einnovator.sso.client.modelx.MemberFilter;
import org.einnovator.sso.client.modelx.RoleFilter;
import org.einnovator.sso.client.modelx.RoleOptions;
import org.einnovator.sso.client.modelx.UserFilter;
import org.einnovator.sso.client.modelx.UserOptions;
import org.einnovator.sso.client.reactive.config.SsoReactiveClientContext;
import org.einnovator.util.MappingUtils;
import org.einnovator.util.PageResult;
import org.einnovator.util.PageUtil;
import org.einnovator.util.model.Application;
import org.einnovator.util.security.SecurityUtil;
import org.einnovator.util.web.RequestOptions;
import org.einnovator.util.web.Result;
import org.einnovator.util.web.WebUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodySpec;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * A Reactive client to EInnovator SSO Gateway.
 * 
 * <p>Provide methods for all server endpoints and resource types. 
 * <p>Including: {@link User}, {@link Group}, {@link Member}, {@link Invitation}, {@link Role}, {@link Client}
 * <p>Errors are propagated using Java runtime exceptions.
 * <p>For caching enabled "high-level" API, see Manager classes.
 * <p>{@code SsoClientConfiguration} specifies configuration details, including server URL and client credentials.
 * <p>Property {@link #getConfig()} provides the default {@code SsoClientConfiguration} to use.
 * <p>All API methods that invoke a server endpoint accept an <em>optional</em> tail parameter to connect to alternative server
 *  (e.g. for cover the less likely case where an application need to connect to multiple servers in different clusters).
 * <p>Internally, {@code SsoClient} uses a {@code WebClient} to invoke remote server.
 * <p>When setup as a <b>Spring Bean</b> both {@code SsoClientConfiguration} and {@code WebClient} are auto-configured.
 * <p>Requests use a session-scoped  {@code OAuth2ClientContext} if running in a web-environment.
 * <p>If the invoking thread does not have an associated web session, the default behavior is to fallback to use a {@code OAuth2ClientContext} 
 * with client credentials. This can be disabled by setting property {@link #web} to false.
 * <p>Method {@link #register()} can be used to register custom application roles with server.
 * <p>This is automatically performed by if configuration property {@code sso.registration.roles.auto} is set to true.
 * 
 * @see org.einnovator.sso.client.manager.UserManager
 * @see org.einnovator.sso.client.manager.GroupManager
 * @see org.einnovator.sso.client.manager.RoleManager
 * @see org.einnovator.sso.client.manager.InvitationManager
 * @see org.einnovator.sso.client.manager.ClientManager
 * 
 * @author support@einnovator.org
 *
 */
public class SsoReactiveClient {

	private final Log logger = LogFactory.getLog(getClass());

	private SsoClientConfiguration config;

	@Autowired
	@Qualifier("ssoWebClient")
	private WebClient webClient;

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;

	private OAuth2ClientContext oauth2ClientContext0 = new DefaultOAuth2ClientContext();

	private WebClient webClient0;

	private boolean autoSetupToken;
	
	@Autowired(required=false)
	private Application application;

	private boolean web = true;
	
	/**
	 * Create instance of {@code SsoClient}.
	 *
	 * @param config the {@code SsoClientConfiguration}
	 */
	@Autowired
	public SsoReactiveClient(SsoClientConfiguration config) {
		this.config = config;
	}

	/**
	 * Create instance of {@code SsoClient}.
	 *
	 * @param webClient the {@code WebClient} used for HTTP transport
	 * @param config the {@code SsoClientConfiguration}
	 */
	public SsoReactiveClient(WebClient webClient, SsoClientConfiguration config) {
		this.config = config;
		this.webClient = webClient;
		this.oauth2ClientContext = null; //TODO
	}

	/**
	 * Create instance of {@code SsoClient}.
	 *
	 * @param webClient the {@code WebClient} used for HTTP transport
	 * @param config the {@code SsoClientConfiguration}
	 * @param web true if auto-detect web-environment 
	 */
	public SsoReactiveClient(WebClient webClient, SsoClientConfiguration config, boolean web) {
		this(webClient, config);
		this.web = web;
	}


	/**
	 * Get the value of property {@code application}.
	 *
	 * @return the application
	 */
	public Application getApplication() {
		return application;
	}

	/**
	 * Set the value of property {@code application}.
	 *
	 * @param application the application to set
	 */
	public void setApplication(Application application) {
		this.application = application;
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
	 * @param config the config to set
	 */
	public void setConfig(SsoClientConfiguration config) {
		this.config = config;
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
	 * @param webClient the webClient to set
	 */
	public void setWebClient(WebClient webClient) {
		this.webClient = webClient;
	}

	/**
	 * Get the value of property {@code oauth2ClientContext}.
	 *
	 * @return the oauth2ClientContext
	 */
	public OAuth2ClientContext getOauth2ClientContext() {
		return oauth2ClientContext;
	}

	/**
	 * Set the value of property {@code oauth2ClientContext}.
	 *
	 * @param oauth2ClientContext the oauth2ClientContext to set
	 */
	public void setOauth2ClientContext(OAuth2ClientContext oauth2ClientContext) {
		this.oauth2ClientContext = oauth2ClientContext;
	}

	/**
	 * Get the value of property {@code oauth2ClientContext0}.
	 *
	 * @return the oauth2ClientContext0
	 */
	public OAuth2ClientContext getOauth2ClientContext0() {
		return oauth2ClientContext0;
	}

	/**
	 * Set the value of property {@code oauth2ClientContext0}.
	 *
	 * @param oauth2ClientContext0 the oauth2ClientContext0 to set
	 */
	public void setOauth2ClientContext0(OAuth2ClientContext oauth2ClientContext0) {
		this.oauth2ClientContext0 = oauth2ClientContext0;
	}

	/**
	 * Get the value of property {@code webClient0}.
	 *
	 * @return the webClient0
	 */
	public WebClient getWebClient0() {
		return webClient0;
	}

	/**
	 * Set the value of property {@code webClient0}.
	 *
	 * @param webClient0 the webClient0 to set
	 */
	public void setWebClient0(WebClient webClient0) {
		this.webClient0 = webClient0;
	}

	/**
	 * Get the value of property {@code web}.
	 *
	 * @return the web
	 */
	public boolean isWeb() {
		return web;
	}

	/**
	 * Set the value of property {@code web}.
	 *
	 * @param web the value of property web
	 */
	public void setWeb(boolean web) {
		this.web = web;
	}

	public boolean isAutoSetupToken() {
		return autoSetupToken;
	}


	public void setAutoSetupToken(boolean autoSetupToken) {
		this.autoSetupToken = autoSetupToken;
	}


	//
	// Registration
	//

	/**
	 * Register client application data with default server using default configured {@code SsoRegistration}.
	 * 
	 * @see SsoClientConfiguration
	 * @see SsoRegistration
	 */
	public void register() {
		SsoRegistration registration = config.getRegistration();
		if (registration!=null) {
			if (application!=null) {
				registration.setApplication(application);
			}
			try {
				register(registration);							
			} catch (RuntimeException e) {
				throw e;
			}
		}
	}

	/**
	 * Register client application data with default server using client credentials.
	 * 
	 * @param registration the {@code SsoRegistration}
	 */
	public void register(SsoRegistration registration) {
		setupClientToken(oauth2ClientContext0);
		register(registration, makeClientWebClient());
	}

	/**
	 * Register client application data.
	 * 
	 * <p><b>Required Security Credentials</b>: Client or Admin (global role ADMIN).
	 * 
	 * @param registration the {@code SsoRegistration}
	 * @param webClient the {@code WebClient} used to connect to server
	 */
	public void register(SsoRegistration registration, WebClient webClient) {
		URI uri = makeURI(SsoEndpoints.register(config));
		RequestEntity<SsoRegistration> request = RequestEntity.post(uri).body(registration);
		retrieveBodyToFlux(webClient, request, Void.class);
	}
	
	//
	// User
	//
	
	/**
	 * Get a {@code Mono} for {@code User} with specified identifier.
	 * 
	 * Identifier {@code id} is the value of a property with unique constraints, that is:
	 * UUID, username, email.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on each {@code User} privacy settings.
	 * 
	 * @param id the identifier
	 * @param options (optional) the {@code UserOptions} that tailor which fields are returned (projection)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code User}
	 */
	public Mono<User> getUserMono(String id, UserOptions options, SsoReactiveClientContext context) {
		id = encodeId(id);
		URI uri = makeURI(SsoEndpoints.user(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, User.class, context);
	}
	
	
	/**
	 * Get a {@code Mono} for the list of {@code User}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code User} privacy settings.
	 * 
	 * @param filter a {@code UserFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for a {@code Page} with {@code User}s
	 */
	public Mono<Page<User>> listUsersMono(UserFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.users(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, User.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code User}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code User} privacy settings.
	 * 
	 * @param filter a {@code UserFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code User}s
	 */
	public Flux<User> listUsersFlux(UserFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.usersFlux(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, User.class, context);
	}

	/**
	 * Deferred create of a new {@code User}.
	 * 
	 * 
	 * <p><b>Required Security Credentials</b>: Client or Admin (global role ADMIN).
	 * 
	 * @param user the {@code User}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the deferred created {@code User}
	 */
	public Mono<URI> createUser(User user, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.users(config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<User> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(user);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Update existing {@code User}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), or owner.
	 * 
	 * @param user the {@code User}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> updateUser(User user, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.user(user.getId(), config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<User> request = RequestEntity.put(uri).accept(MediaType.APPLICATION_JSON).body(user);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	/**
	 * Deferred Delete existing {@code User}
	 * 
	 * Identifier {@code id} is the value of a property with unique constraints, that is:
	 * UUID, username, email.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), or owner.
	 * 
	 * @param id the {@code User} identifier
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> deleteUser(String id, RequestOptions options, SsoReactiveClientContext context) {
		id = encodeId(id);
		URI uri = makeURI(SsoEndpoints.user(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	

	//
	// Password
	// 

	/**
	 * Deffered change a {@code User} password.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * 
	 * @param password the password
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> changePassword(String password, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.password(config, isAdminRequest(options, context)) + "?password=" + password);
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}

	
	//
	// Group
	//
	

	/**
	 * Get a {@code Mono} for a {@code Group} with specified identifier.
	 * 
	 * Identifier {@code id} is the value of a property with unique constraints, that is:
	 * UUID, name for root {@code Groups} if server is configured to required unique names for root {@code Group}s .
	 * 
	 * <p><b>Required Security Credentials</b>: any for root {@code Group}, but results depend on each {@code User} privacy settings.
	 *
	 * @param groupId the identifier
	 * @param filter (optional) the {@code GroupOptions} that tailor which fields are returned (projection) and {@code GroupFilter} for sub-groups
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code Group}
	 */
	public Mono<Group> getGroupMono(String groupId, GroupFilter filter, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		URI uri = makeURI(SsoEndpoints.group(groupId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Group.class, context);
	}
	
	/**
	 * List {@code Group}s.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings.
	 * 
	 * @param filter a {@code GroupFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for a {@code Page} with {@code Group}s
	 */
	public Mono<Page<Group>> listGroupsMono(GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.groups(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, Group.class));
	}

	/**
	 * Get a {@code Flux} for the list of {@code Group}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code Group} privacy settings.
	 * 
	 * @param filter a {@code GroupFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code Group}s
	 */
	public Flux<Group> listGroupsFlux(GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.groupsFlux(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, Group.class, context);
	}
	
	/**
	 * Deferred create of a new {@code Group}.
	 * 
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), any for root {@code Group}s. 
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param group the {@code Group}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the deferred created {@code Group}
	 */
	public Mono<URI> createGroup(Group group, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.groups(config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Group> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(group);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}

	/**
	 *  Deferred  Update existing {@code Group}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN).
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param group the {@code Group}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> updateGroup(Group group, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.group(encode(group.getId()), config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Group> request = RequestEntity.put(uri).accept(MediaType.APPLICATION_JSON).body(group);		
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}

	/**
	 * Deferred Delete existing {@code Group}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN).
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param id the {@code Group} identifier
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> deleteGroup(String id, RequestOptions options, SsoReactiveClientContext context) {
		id = encode(id);
		URI uri = makeURI(SsoEndpoints.group(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	//
	// Group Tree
	//

	/**
	 * Get a {@code Mono} for the list of sub-{@code Group}s.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings.
	 * 
	 * @param id the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param direct true if count only direct sub-group, false if count the all tree
	 * @param filter a {@code GroupFilter} to filter sub-groups
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for a {@code Page} with {@code Group}s
	 
	 */	
	public Mono<Page<Group>> listSubGroupsMono(String id, boolean direct, GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		id = encode(id);
		if (filter==null) {
			filter = new GroupFilter();			
		}
		if (direct) {
			filter.setParent(id);			
		} else {
			filter.setRoot(id);
		}
		return listGroupsMono(filter, pageable, context);
	}


	/**
	 * Get a {@code Flux} for the list of sub-{@code Group}s.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings.
	 * 
	 * @param id the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param direct true if count only direct sub-group, false if count the all tree
	 * @param filter a {@code GroupFilter} to filter sub-groups
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for {@code Group}s
	 */	
	public Flux<Group> listSubGroupsFlux(String id, boolean direct, GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		id = encode(id);
		if (filter==null) {
			filter = new GroupFilter();			
		}
		if (direct) {
			filter.setParent(id);			
		} else {
			filter.setRoot(id);
		}
		return listGroupsFlux(filter, pageable, context);
	}
	
	/**
	 * Get {@code Mono} for Count of {@code Group}s matching specified {@code GroupFilter}.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings.
	 * 
	 * @param filter a {@code GroupFilter}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the count of {@code Group}s
	 */	
	public Mono<Integer> countGroups(GroupFilter filter, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.countGroups(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Integer.class, context);
	}
	
	/**
	 * Get {@code Mono} Count number of sub-{@code Group}s for specified {@code Group}.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings.
	 * 
	 * @param id the {@code id} identifier (UUID, or name of root group if supported)
	 * @param direct true if count only direct sub-group, false if count the all tree
	 * @param filter a {@code GroupFilter}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Page} with {@code Group}s
	 * @return a {@code Mono} for the count of {@code Group}s	 
	 */	
	public Mono<Integer> countSubGroups(String id, boolean direct, GroupFilter filter, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new GroupFilter();			
		}
		if (direct) {
			filter.setParent(id);			
		} else {
			filter.setRoot(id);
		}
		return countGroups(filter, context);
	}

	//
	// Group Members
	//
	
	/**
	 * Get a {@code Mono} for the list of {@code Member} of a {@code Group} .
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param filter a {@code MemberFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for a {@code Page} with {@code Member}s
	 */	
	public Mono<Page<Member>> listGroupMembersMono(String groupId, MemberFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		URI uri = makeURI(SsoEndpoints.groupMembers(groupId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, Member.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code Member} of a {@code Group} .
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param filter a {@code MemberFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code Flux} with list of {@code Member}s
	 */	
	public Flux<Member> listGroupMembersFlex(String groupId, MemberFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		URI uri = makeURI(SsoEndpoints.groupMembersFlux(groupId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, Member.class, context);
	}

	/**
	 * Get count of {@code Member} in a {@code Group} .
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param id the {@code id} identifier (UUID, or name of root group if supported)
	 * @param filter a {@code MemberFilter}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the count of {@code Member} (users)
	 
	 */	
	public Mono<Integer> countGroupMembers(String id, MemberFilter filter, SsoReactiveClientContext context) {
		id = encode(id);
		URI uri = makeURI(SsoEndpoints.countMembers(id, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Integer.class, context);
	}

	/**
	 * Get a {@code Mono} for a {@code Member} with specified identifier.
	 * 
	 * Identifier {@code id} is the value of a property with unique constraints, that is:
	 * UUID of {@code member}, of username od {@code User}
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param options optional {@code UserOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code Member} for the {@code Member}	 
	 */
	public Mono<Member> getGroupMemberMono(String groupId, String userId, UserOptions options, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		userId = encodeId(userId);
		URI uri = makeURI(SsoEndpoints.member(groupId, userId, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Member.class, context);
	}

	/**
	 * Deferred Add user a new {@code Group}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), any for root {@code Group}s. 
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the created {@code Member}
	 
	 */
	public Mono<URI> addMemberToGroup(String userId, String groupId, RequestOptions options, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		userId = encodeId(userId);
		URI uri = makeURI(SsoEndpoints.groupMembers(groupId, config, isAdminRequest(options, context)) + "?username=" + userId);
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).build();		
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Add user a new {@code Group}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), any for root {@code Group}s. 
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param member the {@code Member} to add to Group
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the created {@code Member}
	 
	 */
	public Mono<URI> addMemberToGroup(Member member, String groupId, RequestOptions options, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		URI uri = makeURI(SsoEndpoints.groupMembers(groupId, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Member> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(member);		
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Remove {@code User} from a {@code Group}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param groupId the {@code Group} identifier (UUID, or name of root group if supported)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 
	 */
	public Mono<Void> removeMemberFromGroup(String userId, String groupId, RequestOptions options, SsoReactiveClientContext context) {
		groupId = encode(groupId);
		userId = encodeId(userId);
		URI uri = makeURI(SsoEndpoints.groupMembers(groupId, config, isAdminRequest(options, context)) + "?username=" + userId);
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	/**
	 * Get a {@code Mono} for the list {@code Group}s a {@code User} is member.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param filter a {@code UserFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} with {@code Page} with {@code Group}s
	 
	 */	
	public Mono<Page<Group>> listGroupsForUserMono(String userId,  GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new GroupFilter();			
		}
		filter.setOwner(userId);
		return listGroupsMono(filter, pageable, context);
	}
	
	/**
	 * Get a {@code Flux} for the list {@code Group}s a {@code User} is member.
	 * 
	 * <p><b>Required Security Credentials</b>: any, but results depend on each {@code Group}, parent and root {@code Group} privacy settings,
	 * and each {@code User} privacy settings.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param filter a {@code UserFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} with a list of {@code Group}s
	 
	 */	
	public Flux<Group> listGroupsForUserFlux(String userId,  GroupFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new GroupFilter();			
		}
		filter.setOwner(userId);
		return listGroupsFlux(filter, pageable, context);
	}

	//
	// Invitation
	//
	
	
	/**
	 * Get a {@code Mono} for a {@code Invitation} with specified identifier.
	 * 
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner.
	 *
	 * @param id the identifier (UUID)
	 * @param options optional  {@code InvitationOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code Invitation}
	 */
	public Mono<Invitation> getInvitationMono(String id, InvitationOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitation(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Invitation.class, context);
	}

	/**
	 *  Get a {@code Mono} for the list of {@code Invitation}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global invitation ADMIN) for global Invitations and group Invitations prototypes. 
	 * <p>For root {@code Group}s: owner or invitation <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or invitation <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or invitation <b>PERMISSION_MANAGER</b>, owner or invitation <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or invitation <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param filter a {@code InvitationFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Page} with {@code Invitation}s
	 */	
	public Mono<Page<Invitation>> listInvitations(InvitationFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitations(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, Invitation.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code Invitation}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code Invitation} privacy settings.
	 * 
	 * @param filter a {@code InvitationFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code Invitation}s
	 */
	public Flux<Invitation> listInvitationsFlux(InvitationFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitationsFlux(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, Invitation.class, context);
	}

	/**
	 * Deferred Create a new {@code Invitation}.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), any. 
	 * 
	 * @param invitation the {@code Invitation}
	 * @param options the {@code InvitationOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the created {@code Invitation}
	 */
	public Mono<URI> invite(Invitation invitation, InvitationOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invite(config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Invitation> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(invitation);		
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Update existing {@code Invitation}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), or owner.
	 * 
	 * @param invitation the {@code Invitation}
	 * @param options optional  {@code InvitationOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> updateInvitation(Invitation invitation, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitation(invitation.getUuid(), config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Invitation> request = RequestEntity.put(uri).accept(MediaType.APPLICATION_JSON).body(invitation);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}

	
	/**
	 * Get  a {@code Mono} for {@code InvitationStats} with {@code Invitation} statistics.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN).
	 *
	 * @param options optional  {@code InvitationOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code InvitationStats}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<InvitationStats> getInvitationStats(RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitationStats(config, isAdminRequest(options, context)));
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, InvitationStats.class, context);
	}

	/**
	 * Get {@code Mono} with invitation {@code URI} with token for specified {@code Invitation}.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner.
	 *
	 * @param id the identifier of the {@code Invitation} (UUID)
	 * @param options optional  {@code InvitationOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the invitation token as an {@code URI}
	 
	 */
	public Mono<URI> getInvitationToken(String id, InvitationOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitationToken(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).build();		
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Delete existing {@code Invitation}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), or owner.
	 * 
	 * @param id the identifier (UUID)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> deleteInvitation(String id, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.invitation(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}

	//
	// Role
	// 
	

	/**
	 * Get a {@code Mono} for a {@code Role} with specified identifier.
	 * 
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 *
	 * @param id the {@code Role} identifier (UUID)
	 * @param options the {@code RoleOptions} (options)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code Role}
	 */
	public Mono<Role> getRoleMono(String id, RoleOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.role(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Role.class, context);
	}
	
	/**
	 *  Get a {@code Mono} for the list of {@code Role}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param filter a {@code RoleFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Page} with {@code Role}s
	 
	 */	
	public Mono<Page<Role>> listRolesMono(RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.roles(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, Role.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code Role}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code Role} privacy settings.
	 * 
	 * @param filter a {@code RoleFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code Role}s
	 */
	public Flux<Role> listRolesFlux(RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.rolesFlux(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, Role.class, context);
	}

	/**
	 * Deferred Create a new {@code Role}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param role the {@code Role}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the created {@code Role}
	 
	 */
	public Mono<URI> createRole(Role role, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.roles(config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Role> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(role);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Update existing {@code Role}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param role the {@code Role}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> updateRole(Role role, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.role(role.getId(), config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Role> request = RequestEntity.put(uri).accept(MediaType.APPLICATION_JSON).body(role);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	
	
	/**
	 * Deferred Delete existing {@code Role}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param id the {@code Role} identifier (UUID)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> deleteRole(String id, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.role(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	//
	// Role Bindings/Assignments
	//
	
	/**
	 * Get a {@code Mono} for the list of {@code User}s assigned to a {@code Role} .
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param roleId the {@code Role} identifier (UUID)
	 * @param filter a {@code UserFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Page} with {@code User}s
	 
	 */	
	public Mono<Page<User>> listRoleMembersMono(String roleId, UserFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.roleMembers(roleId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, User.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code User}s assigned to a {@code Role} .
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param roleId the {@code Role} identifier (UUID)
	 * @param filter a {@code UserFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Page} with {@code User}s
	 
	 */	
	public Flux<User> listRoleMembersFlux(String roleId, UserFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.roleMembersFlux(roleId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, User.class, context);
	}

	/**
	 * Get count of {@code User}s assigned a {@code Role} .
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN) for global Roles and group Roles prototypes. 
	 * <p>For root {@code Group}s: owner or role <b>PERMISSION_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * For sub{@code Group}s: owner or role <b>PERMISSION_MANAGER</b>, owner or role <b>PERMISSION_MANAGER</b> in parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param roleId the {@code Role} identifier (UUID)
	 * @param filter a {@code UserFilter} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code User} count
	 
	 */	
	public Mono<Integer> countRoleMembers(String roleId, UserFilter filter, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.countRoleMembers(roleId, config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Integer.class, context);
	}

	/**
	 * Assign {@code Role} to {@code User}
	 * 
	 * Request ignored if {@code User} is already assigned the {@code Role}.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), any for root {@code Group}s. 
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param roleId the {@code Role} identifier (UUID)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 
	 */
	public void assignRole(String userId, String roleId, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.roleMembers(roleId, config, isAdminRequest(options, context)) + "?username=" + userId);
		userId = encodeId(userId);
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).build();
		retrieveBodyToFlux(request, Void.class, context);
	}
	
	/**
	 * Unassign {@code Role} from {@code User}
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param roleId the {@code Role} identifier (UUID)
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 
	 */
	public void unassignRole(String userId, String roleId, RequestOptions options, SsoReactiveClientContext context) {
		userId = encodeId(userId);
		URI uri = makeURI(SsoEndpoints.roleMembers(roleId, config, isAdminRequest(options, context)) + "?username=" + userId);
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		retrieveBodyToFlux(request, Void.class, context);
	}
	
	
	/**
	 * Get a {@code Mono} for a list global {@code Role}s a {@code User} is assigned to.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param filter a {@code RoleFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code Mono} for a {@code Page} with {@code Role}s
	 */	
	public Mono<Page<Role>> listRolesForUserMono(String userId, RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new RoleFilter();
		}
		userId = encodeId(userId);
		filter.setRunAs(userId);
		return listRolesMono(filter, pageable, context);
	}

	/**
	 * Get a {@code Flux} for a list global {@code Role}s a {@code User} is assigned to.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param filter a {@code RoleFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code Role}s
	 */	
	public Flux<Role> listRolesForUserFlux(String userId, RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new RoleFilter();
		}
		userId = encodeId(userId);
		filter.setRunAs(userId);
		return listRolesFlux(filter, pageable, context);
	}
	
	/**
	 * Get a {@code Mono} for a list {@code Role}s a {@code User} is assigned to in a {@code Group}.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param groupId the identifier of a {@code Group} (UUID)
	 * @param filter a {@code RoleFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code Mono} for a {@code Page} with {@code Role}s
	 */	
	public Mono<Page<Role>> listRolesForUserInGroupMono(String userId, String groupId, RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new RoleFilter();
		}
		userId = encodeId(userId);
		filter.setRunAs(userId);
		filter.setGroup(groupId);
		return listRolesMono(filter, pageable, context);
	}

	/**
	 * Get a {@code Flux} for a list {@code Role}s a {@code User} is assigned to in a {@code Group}.
	 * 
	 * <p><b>Required Security Credentials</b>: Client, Admin (global role ADMIN), owner {@code User}.
	 * <p>For root {@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}
	 * <p>For sub-{@code Group}s: owner or role <b>GROUP_MANAGER</b> in {@code Group}, owner or role <b>GROUP_MANAGER</b> of parent {@code Group}, or owner or role <b>GROUP_MANAGER</b> of tree root {@code Group}.
	 * 
	 * @param userId the identifier of a {@code User} (UUID, or username)
	 * @param groupId the identifier of a {@code Group} (UUID)
	 * @param filter a {@code RoleFilter} (optional)
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return the {@code Flux} with list of {@code Role}s
	 */	
	public Flux<Role> listRolesForUserInGroupFlux(String userId, String groupId, RoleFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		if (filter==null) {
			filter = new RoleFilter();
		}
		userId = encodeId(userId);
		filter.setRunAs(userId);
		filter.setGroup(groupId);
		return listRolesFlux(filter, pageable, context);
	}

	//
	// Client
	//
	
	/**
	 * Get a {@code Mono} for a {@code Client} with specified identifier.
	 * 
	 * <p><b>Required Security Credentials</b>: Admin (global role ADMIN).
	 * 
	 * @param id the identifier (UUID)
	 * @param options {@code ClientOptions} options (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the {@code Client}	 
	 */
	public Mono<Client> getClientMono(String id, ClientOptions options, SsoReactiveClientContext context) {
		id = encodeId(id);
		URI uri = makeURI(SsoEndpoints.client(id, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToMono(request, Client.class, context);
	}

	/**
	 * Get a {@code Mono} for the list of {@code Client}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code Client} privacy settings.
	 * 
	 * @param filter a {@code ClientFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for a {@code Page} with {@code Client}s
	 */
	public Mono<Page<Client>> listClientsMono(ClientFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.clients(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		@SuppressWarnings("rawtypes")
		Mono<PageResult> mono = retrieveBodyToMono(request, PageResult.class, context);
		return mono.map(r -> PageUtil.create2(r, Client.class));
	}
	
	/**
	 * Get a {@code Flux} for the list of {@code Client}s.
	 * 
	 * <p><b>Required Security Credentials</b>: Any, but results depend on credentials and each {@code Client} privacy settings.
	 * 
	 * @param filter a {@code ClientFilter}
	 * @param pageable a {@code Pageable} (optional)
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Flux} for the list {@code Client}s
	 */
	public Flux<Client> listClientsFlux(ClientFilter filter, Pageable pageable, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.clients(config, isAdminRequest(filter, context)));
		uri = processURI(uri, filter, pageable);
		RequestEntity<Void> request = RequestEntity.get(uri).accept(MediaType.APPLICATION_JSON).build();
		return retrieveBodyToFlux(request, Client.class, context);
	}

	/**
	 * Deferred Create a new {@code Client}
	 * 
	 * <p><b>Required Security Credentials</b>: Admin (global role ADMIN).
	 * 
	 * @param client the {@code Client}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} for the location {@code URI} for the created {@code Client}
	 
	 */
	public Mono<URI> createClient(Client client, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.clients(config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Client> request = RequestEntity.post(uri).accept(MediaType.APPLICATION_JSON).body(client);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.map(r->r.getHeaders().getLocation());
	}
	
	/**
	 * Deferred Update existing {@code Client}
	 * 
	 * <p><b>Required Security Credentials</b>: Admin (global role ADMIN).
	 * 
	 * @param client the {@code Client}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> updateClient(Client client, RequestOptions options, SsoReactiveClientContext context) {
		URI uri = makeURI(SsoEndpoints.client(client.getId(), config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Client> request = RequestEntity.put(uri).accept(MediaType.APPLICATION_JSON).body(client);
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}
	
	/**
	 * Deferred Delete existing {@code Client}
	 * 
	 * <p><b>Required Security Credentials</b>: Admin (global role ADMIN).
	 * 
	 * @param clientId the {@code Client}
	 * @param options optional {@code RequestOptions}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void	 
	 */
	public Mono<Void> deleteClient(String clientId, RequestOptions options, SsoReactiveClientContext context) {
		clientId = encodeId(clientId);
		URI uri = makeURI(SsoEndpoints.client(clientId, config, isAdminRequest(options, context)));
		uri = processURI(uri, options);
		RequestEntity<Void> request = RequestEntity.delete(uri).accept(MediaType.APPLICATION_JSON).build();
		Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request, context);
		return mono.then();
	}

	//
	// HTTP Transport
	//
	
	
	/**
	 * Perform the HTTP request and retrieve the response body as a Flux.
	 * 
	 * If {@code context} is not null, use provided {@code WebClient} if any.
	 * Otherwise, use session scoped {@code WebClient} if in web request thread. 
	 * Otherwise, use client credentials singleton (non thread-safe) @code WebClient}.
	 * 
	 * @param <T> response type
	 * @param request the {@code RequestEntity}
	 * @param responseType the response type
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return result {@code ResponseEntity}
	 
	 */
	protected <T> Flux<T> retrieveBodyToFlux(RequestEntity<?> request, Class<T> responseType, SsoReactiveClientContext context) throws RestClientException {
		WebClient webClient = getRequiredWebClient(context);
		try {
			return retrieveBodyToFlux(webClient, request, responseType);			
		} catch (RuntimeException e) {
			if (context!=null && !context.isSingleton()) {
				context.setResult(new Result<Object>(e));
			}
			throw e;
		}
	}

	/**
	 * Perform the HTTP request and retrieve the response body as a Flux.
	 * 
	 * If {@code context} is not null, use provided {@code WebClient} if any.
	 * Otherwise, use session scoped {@code WebClient} if in web request thread. 
	 * Otherwise, use client credentials singleton (non thread-safe) @code WebClient}.
	 * 
	 * @param <T> response type
	 * @param request the {@code RequestEntity}
	 * @param responseType the response type
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a @{@code Mono} to retrieve body object
	 
	 */
	protected <T> Mono<T> retrieveBodyToMono(RequestEntity<?> request, Class<T> responseType, SsoReactiveClientContext context) throws RestClientException {
		WebClient webClient = getRequiredWebClient(context);
		try {
			return retrieveBodyToMono(webClient, request, responseType);			
		} catch (RuntimeException e) {
			if (context!=null && !context.isSingleton()) {
				context.setResult(new Result<Object>(e));
			}
			throw e;
		}
	}
	
	
	/**
	 * Perform the HTTP request and retrieve a response with no body as a {@code Mono<ResponseEntity<Void>>}.
	 * 
	 * 
	 * @param webClient the {@code WebClient} to use
	 * @param request the {@code RequestEntity}
	 * @return the result {@code ResponseEntity}
	 
	 */
	protected <T> Mono<ResponseEntity<Void>> retrieveBodilessEntityMono(RequestEntity<?> request, SsoReactiveClientContext context) throws RestClientException {
		WebClient webClient = getRequiredWebClient(context);
		try {
			return retrieveBodilessEntityMono(webClient, request);			
		} catch (RuntimeException e) {
			if (context!=null && !context.isSingleton()) {
				context.setResult(new Result<Object>(e));
			}
			throw e;
		}
	}

	/**
	 * Get the {@code WebClient} to use to perform a request.
	 * 
	 * If the context is not null, returns the {@code WebClient} specified by the context (if any).
	 * Otherwise, return the configured {@code WebClient} in property {@link #webClient}.
	 * If property {@link web} is true, check if current thread is bound to a web request with a session-scope. 
	 * If not, fallback to client credential {@code WebClient} in property {@link #webClient2} or create one if needed.
	 * 
	 * @param context optional {@code SsoClientContext}
	 * @return the {@code OAuth2RestTemplate}
	 */
	protected WebClient getRequiredWebClient(SsoReactiveClientContext context) {
		WebClient webClient = this.webClient;
		if (context!=null && context.getWebClient()!=null) {
			webClient = context.getWebClient();
		} else {
			if (WebUtil.getHttpServletRequest()==null && web) {
				if (this.webClient0==null) {
					this.webClient0 = makeClientWebClient(config);
				}
				webClient = this.webClient0;
			}			
		}
		return webClient;
	}
	
	/**
	 * Perform the HTTP request and retrieve the response body as a Flux.
	 * 
	 * 
	 * @param <T> response type
	 * @param webClient the {@code WebClient} to use
	 * @param request the {@code RequestEntity}
	 * @param responseType the response type
	 * @return the result {@code ResponseEntity}
	 
	 */
	protected <T> Flux<T> retrieveBodyToFlux(WebClient webClient, RequestEntity<?> request, Class<T> responseType) throws RestClientException {
		if (autoSetupToken) {
			setupToken();
		}
		RequestBodySpec spec = setup(webClient, request);
		return spec.retrieve().bodyToFlux(responseType);
	}

	/**
	 * Perform the HTTP request and retrieve the response as a {@code Mono<ResponseEntity<T>>}.
	 * 
	 * 
	 * @param <T> response type
	 * @param webClient the {@code WebClient} to use
	 * @param request the {@code RequestEntity}
	 * @param responseType the response type
	 * @return the result {@code ResponseEntity}
	 
	 */
	protected <T> Mono<ResponseEntity<T>> retrieveBodyToEntityMono(WebClient webClient, RequestEntity<?> request, Class<T> responseType) throws RestClientException {
		if (autoSetupToken) {
			setupToken();
		}
		RequestBodySpec spec =  setup(webClient, request);
		setup(webClient, request);
		return spec.retrieve().toEntity(responseType);
	}
	
	/**
	 * Perform the HTTP request and retrieve the response as a {@code Mono<ResponseEntity<T>>}.
	 * 
	 * 
	 * @param <T> response type
	 * @param webClient the {@code WebClient} to use
	 * @param request the {@code RequestEntity}
	 * @param responseType the response type
	 * @return the result {@code ResponseEntity}
	 
	 */
	protected <T> Mono<T> retrieveBodyToMono(WebClient webClient, RequestEntity<?> request, Class<T> responseType) throws RestClientException {
		if (autoSetupToken) {
			setupToken();
		}
		RequestBodySpec spec =  setup(webClient, request);
		setup(webClient, request);
		return spec.retrieve().bodyToMono(responseType);
	}
	
	/**
	 * Perform the HTTP request and retrieve a response with no body as a {@code Mono<ResponseEntity<Void>>}.
	 * 
	 * 
	 * @param webClient the {@code WebClient} to use
	 * @param request the {@code RequestEntity}
	 * @return the result {@code ResponseEntity}
	 */
	protected <T> Mono<ResponseEntity<Void>> retrieveBodilessEntityMono(WebClient webClient, RequestEntity<?> request) throws RestClientException {
		if (autoSetupToken) {
			setupToken();
		}
		RequestBodySpec spec =  setup(webClient, request);
		setup(webClient, request);
		return spec.retrieve().toBodilessEntity();
	}
	
	protected RequestBodySpec setup(WebClient webClient, RequestEntity<?> request) {
		RequestBodySpec spec =  webClient.method(request.getMethod()).uri(request.getUrl());
		if (request.getHeaders()!=null) {
			List<MediaType> types = request.getHeaders().getAccept(); 
			if (types!=null) {
				spec.accept(types.toArray(new MediaType[types.size()]));		
			}
		}
		return spec;
	}
	

	//
	// Client Credentials Token utils
	//
	
	public OAuth2AccessToken setupClientToken() {
		return setupClientToken(oauth2ClientContext);
	}


	public OAuth2AccessToken setupClientToken0() {
		return setupClientToken(oauth2ClientContext0);
	}

	public OAuth2AccessToken setupClientToken(OAuth2ClientContext oauth2ClientContext) {
		return setupClientToken(oauth2ClientContext, false, false, config);
	}

	public OAuth2AccessToken setupClientToken(boolean force, boolean cached) {
		return setupClientToken(oauth2ClientContext, force, cached);
	}

	public OAuth2AccessToken setupClientToken(String clientId, String clientSecret) {
		SsoClientConfiguration config2 = new SsoClientConfiguration(config);
		config2.setClientId(clientId);
		config2.setClientSecret(clientSecret);
		return setupClientToken(oauth2ClientContext, config2);
	}

	public OAuth2AccessToken setupClientToken(OAuth2ClientContext oauth2ClientContext, boolean force, boolean cached) {
		return setupClientToken(oauth2ClientContext, force, cached, config);
	}

	public static OAuth2AccessToken setupClientToken(OAuth2ClientContext oauth2ClientContext, SsoClientConfiguration config) {
		return setupClientToken(oauth2ClientContext, false, false, config);
	}

	public static OAuth2AccessToken setupClientToken(OAuth2ClientContext oauth2ClientContext, boolean force, boolean cached, SsoClientConfiguration config) {
		OAuth2AccessToken token = null;
		if (!force) {
			token = oauth2ClientContext.getAccessToken();
			if (token != null) {
				return token;
			}
		}
		token = getClientToken(oauth2ClientContext, config);

		if (token == null) {
			return null;
		}
		oauth2ClientContext.setAccessToken(token);

		return token;
	}

	public ResourceOwnerPasswordResourceDetails makeResourceOwnerPasswordResourceDetails(String username, String password) {
		return SsoClient.makeResourceOwnerPasswordResourceDetails(username, password, config);
	}
	

	public static OAuth2AccessToken getClientToken(OAuth2ClientContext oauth2ClientContext, SsoClientConfiguration config) {
		ClientCredentialsResourceDetails resource = SsoClient.makeClientCredentialsResourceDetails(config.getClientId(), config.getClientSecret(), config);
		WebClient webClient = makeClientWebClient(resource, oauth2ClientContext, false);
		OAuth2AccessToken token = getOAuth2AccessToken(webClient);
		return token;
	}


	public OAuth2AccessToken getClientToken(OAuth2ClientContext oauth2ClientContext) {
		return getClientToken(oauth2ClientContext, config);
	}
	

	//
	// Token utils
	//
	
	/**
	 * Get or request new {@code OAuth2AccessToken} for the session user.
	 * 
	 * @return the {@code OAuth2AccessToken}
	 */
	public OAuth2AccessToken setupToken() {
		return setupToken(false);
	}

	/**
	 * Get or request new {@code OAuth2AccessToken} for the session user.
	 * 
	 * @param force true if not checking if token is already available locally
	 * @return the {@code OAuth2AccessToken}
	 */
	public OAuth2AccessToken setupToken(boolean force) {
		OAuth2AccessToken token = null;

		if (!force) {
			token = oauth2ClientContext.getAccessToken();
			if (token != null) {
				return token;
			}
		}

		token = getToken();
		if (token == null) {
			logger.warn("setupToken: No token found");
			return null;
		}
		oauth2ClientContext.setAccessToken(token);
		return token;
	}

	/**
	 * Get {@code OAuth2AccessToken} for specified user using the session-scoped {@code OAuth2ClientContext}.
	 * 
	 * @param username the username
	 * @param password the user password
	 * @return the {@code OAuth2AccessToken}
	 */
	public OAuth2AccessToken getToken(String username, String password) {
		return getToken(username, password, oauth2ClientContext);
	}

	/**
	 * Get {@code OAuth2AccessToken} for specified user using specified {@code OAuth2ClientContext}.
	 * 
	 * @param username the username
	 * @param password the user password
	 * @param oauth2ClientContext the {@code OAuth2ClientContext}
	 * @return the {@code OAuth2AccessToken}
	 */
	public OAuth2AccessToken getToken(String username, String password, OAuth2ClientContext oauth2ClientContext) {
		ResourceOwnerPasswordResourceDetails resource = makeResourceOwnerPasswordResourceDetails(username, password);
		WebClient webClient = makeWebClient(resource, oauth2ClientContext);
		OAuth2AccessToken token = getOAuth2AccessToken(webClient);
		return token;
	}

	private static OAuth2AccessToken getOAuth2AccessToken(WebClient webClient) {
		return null;
	}

	public OAuth2AccessToken getSessionToken() {
		return oauth2ClientContext.getAccessToken();
	}
	
	//
	// Static Token utils
	//

	/**
	 * Static utility to get OAuth2 Token value from an {@code OAuth2Authentication}.
	 * 
	 * @param authentication the {@code Authentication}
	 * @return the token value
	 */
	public static OAuth2AccessToken getToken(Authentication authentication) {
		String tokenValue = getTokenValue(authentication);
		if (tokenValue == null) {
			return null;
		}
		return new DefaultOAuth2AccessToken(tokenValue);
	}


	/**
	 * Static utility to get OAuth2 Token for the {@code Principal}.
	 * 
	 * @param principal the {@code Principal}
	 * @return the token value
	 */
	public static OAuth2AccessToken getToken(Principal principal) {
		String tokenValue = getTokenValue(principal);
		if (tokenValue == null) {
			return null;
		}
		return new DefaultOAuth2AccessToken(tokenValue);
	}

	/**
	 * Static utility to get OAuth2 Token value for the {@code Principal}.
	 * 
	 * @return the token value
	 */
	public static OAuth2AccessToken getToken() {
		return getToken(SecurityUtil.getAuthentication());
	}


	/**
	 * Static utility to get OAuth2 Token value for the {@code Principal} as setup in the {@code SecurityContext}.
	 * 
	 * @return the token value
	 */
	public static String getTokenValue() {
		return getTokenValue(SecurityUtil.getAuthentication());
	}

	/**
	 * Static utility to get OAuth2 Token value for the {@code Principal}.
	 * 
	 * @param principal the {@code Principal}
	 * @return the token value
	 */
	public static String getTokenValue(Principal principal) {
		if (principal == null) {
			return null;
		}
		if (!(principal instanceof Authentication)) {
			return null;
		}
		return getTokenValue((Authentication) principal);
	}

	/**
	 * Static utility to get OAuth2 Token value from an {@code OAuth2Authentication}.
	 * 
	 * @param authentication the {@code Authentication}
	 * @return the token value
	 */
	public static String getTokenValue(Authentication authentication) {
		if (!(authentication instanceof OAuth2Authentication)) {
			return null;
		}
		OAuth2Authentication oauth2 = (OAuth2Authentication) authentication;
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) oauth2.getDetails();
		if (details == null) {
			return null;
		}
		return details.getTokenValue();
	}

	/**
	 * Static utility to get type of OAuth2 Token for the {@code Principal}.

	 * @param principal the {@code Principal}
	 * @return the token type
	 */
	public static String getTokenType(Principal principal) {
		if (principal == null) {
			return null;
		}
		if (!(principal instanceof OAuth2Authentication)) {
			return null;
		}
		OAuth2Authentication oauth2 = (OAuth2Authentication) principal;
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) oauth2.getDetails();
		return details.getTokenType();
	}

	/**
	 * Static utility to get type of OAuth2 Token session Id.

	 * @param principal the {@code Principal}
	 * @return the session ID
	 */
	public static String getSessionId(Principal principal) {
		if (principal == null) {
			return null;
		}
		if (!(principal instanceof OAuth2Authentication)) {
			return null;
		}
		OAuth2Authentication oauth2 = (OAuth2Authentication) principal;
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) oauth2.getDetails();
		return details.getSessionId();
	}


	//
	// Factory utils
	//
	
	/**
	 * Static utility factory method to create an instance of {@code SsoClient} with client credentials.
	 * 
	 * @param config the {@code SsoClientConfiguration} with server URL, client credentials and other properties
	 * @return the {@code SsoClient}
	 */
	public static SsoReactiveClient makeSsoClient(SsoClientConfiguration config) {
		OAuth2ClientContext context = new DefaultOAuth2ClientContext();
		OAuth2ProtectedResourceDetails resource = SsoClient.makeClientCredentialsResourceDetails(config);
		WebClient webClient = makeWebClient(resource, context);
		SsoReactiveClient ssoClient = new SsoReactiveClient(webClient, config);
		return ssoClient;
	}

	/**
	 * Static utility factory method to create an instance of {@code SsoClient} with user credentials.
	 * 
	 * @param username the username
	 * @param password the user password
	 * @param config the {@code SsoClientConfiguration} with server URL, client credentials and other properties
	 * @return the {@code SsoClient}
	 */
	public static SsoReactiveClient makeReactiveSsoClient(String username, String password, SsoClientConfiguration config) {
		OAuth2ClientContext context = new DefaultOAuth2ClientContext();
		OAuth2ProtectedResourceDetails resource = SsoClient.makeResourceOwnerPasswordResourceDetails(username, password, config);
		WebClient webClient = makeWebClient(resource, context);
		SsoReactiveClient ssoClient = new SsoReactiveClient(webClient, config);
		return ssoClient;
	}

	//
	// Principal utils
	//
	
	/**
	 * Get {@code User} for {@code Principal} in {@code SessionContext} using local context data initialized from <b>/userinfo</b> endpoint of server.
	 * 
	 * @return the {@code User}
	 */
	public static final User getPrincipalUser() {
		 Map<String, Object> details = SecurityUtil.getPrincipalDetails();
		 return MappingUtils.convert(details, User.class);
	}
	
	//
	// Logout
	//
	
	
	/**
	 * Force logout.
	 * 
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> doLogout(SsoReactiveClientContext context) {
		@SuppressWarnings("rawtypes")
		RequestEntity request2 = RequestEntity.post(makeURI(SsoEndpoints.getTokenRevokeEndpoint(config)))
				.accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON).build();
		try {
			Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request2, context);
			if (logger.isDebugEnabled()) {
				logger.debug("logout:");					
			}
			return mono.then();
		} catch (RuntimeException e) {
			logger.error("logout:" + e);
			return Mono.error(e);
		}
	}

	/**
	 * Force logout.
	 * 
	 * @param authentication the {@code Authentication}
	 * @param context optional {@code SsoReactiveClientContext}
	 * @return a {@code Mono} of void
	 */
	public Mono<Void> doLogout(Authentication authentication, SsoReactiveClientContext context) {
		if (authentication == null) {
			return Mono.empty();
		}
		Object details = authentication.getDetails();
		if (details.getClass().isAssignableFrom(OAuth2AuthenticationDetails.class)) {
			String accessToken = ((OAuth2AuthenticationDetails) details).getTokenValue();
			SsoClientConfiguration config = this.config;
			if (context!=null && context.getConfig()!=null) {
				config = context.getConfig();
			}
			@SuppressWarnings("rawtypes")
			RequestEntity request2 = RequestEntity.post(makeURI(SsoEndpoints.getTokenRevokeEndpoint(config)))
					.accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON)
					.header("Authorization", "Bearer " + accessToken).build();
			try {
				WebClient webClient = makeWebClient();
				Mono<ResponseEntity<Void>> mono = retrieveBodilessEntityMono(request2, context);
				if (logger.isDebugEnabled()) {
					logger.debug("logout:");					
				}
				return mono.then();

			} catch (RuntimeException e) {
				logger.error("logout:" + e);
				return Mono.error(e);
			}
		}
		return Mono.empty();
	}

	/**
	 * Force logout.
	 * 
	 * @param session the {@code HttpSession}
	 */
	public void doLogout(HttpSession session) {
		if (session != null) {
			logger.debug("Invalidating session: " + session.getId());
			session.invalidate();
		}
		SecurityContext context = SecurityContextHolder.getContext();
		if (context != null) {
			context.setAuthentication(null);
			SecurityContextHolder.clearContext();
		}
	}

	//
	// WebClient utils
	// 

	/**
	 * Make a {@code WebClient} to connect to server specified by a {@code OAuth2ProtectedResourceDetails}.
	 * 
	 * @param resource the {@code OAuth2ProtectedResourceDetails}
	 * @param oauth2ClientContext the {@code OAuth2ClientContext}
	 * @return the {@code WebClient}
	 */
	public static WebClient makeWebClient(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext oauth2ClientContext) {
		//ClientHttpRequestFactory clientHttpRequestFactory = config.getConnection().makeClientHttpRequestFactory();
		//webClient.setRequestFactory(clientHttpRequestFactory); //TODO
		return makeWebClient(resource, oauth2ClientContext);
	}
	
	/**
	 * Make a {@code WebClient} to connect to default server.
	 * 
	 * @param oauth2ClientContext the {@code OAuth2ClientContext}
	 * @return the {@code WebClient}
	 */
	public WebClient makeWebClient(OAuth2ClientContext oauth2ClientContext) {
		return makeWebClient(config, oauth2ClientContext);
	}
	
	/**
	 * Make a {@code WebClient} to connect to default server.
	 * 
	 * @return the {@code WebClient}
	 */
	public WebClient makeWebClient() {
		return makeWebClient(oauth2ClientContext);
	}
	
	/**
	 * Make a {@code WebClient} to connect to server specified by configuration {@code SsoClientConfiguration}.
	 * 
	 * @param config the {@code SsoClientConfiguration}
	 * @param oauth2ClientContext the {@code OAuth2ClientContext}
	 * @return the {@code WebClient}
	 */
	public WebClient makeWebClient(SsoClientConfiguration config, OAuth2ClientContext oauth2ClientContext) {
		ClientCredentialsResourceDetails resource = SsoClient.makeClientCredentialsResourceDetails(config);
		//ClientHttpRequestFactory clientHttpRequestFactory = config.getConnection().makeClientHttpRequestFactory();
		//webClient.setRequestFactory(clientHttpRequestFactory);
		return makeWebClient(resource, oauth2ClientContext);
	}

	
	public static WebClient makeWebClient(SsoClientConfiguration config, SsoReactiveClientContext context) {
		return WebClient.builder()
				.build();
	}

	
	/**
	 * Make a {@code WebClient} to connect to default server with Client credentials in singleton {@code OAuth2ClientContext}.
	 * 
	 * Sets the created {@code WebClient} as value of property {@code webClient0} if currently null.
	 * 
	 * @return the {@code WebClient}
	 */
	public WebClient makeClientWebClient() {
		if (webClient0==null) {
			webClient0 = makeWebClient(oauth2ClientContext0);
		}
		return webClient0;
	}
	
	public static WebClient makeClientWebClient(SsoClientConfiguration config, boolean setup) {
		return makeClientWebClient(config, new DefaultOAuth2ClientContext(), setup);
	}

	public static WebClient makeClientWebClient(SsoClientConfiguration config, OAuth2ClientContext context, boolean setup) {
		ClientCredentialsResourceDetails credentials = SsoClient.makeClientCredentialsResourceDetails(config);
		return makeClientWebClient(credentials, context, setup);	
	}
	

	private static WebClient makeClientWebClient(ClientCredentialsResourceDetails resource, OAuth2ClientContext context, boolean setup) {
		WebClient webClient = WebClient.builder()
				.build();
		if (setup) {
			//setupClientToken(webClient.getOAuth2ClientContext(), config);			
		}
		return webClient;
	}

	public static WebClient makeClientWebClient(SsoClientConfiguration config) {
		return makeClientWebClient(config, true);
	}



}
