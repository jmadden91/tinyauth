package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

func NewHandlers(handlersConfig types.HandlersConfig, auth *auth.Auth, hooks *hooks.Hooks, providers *providers.Providers, docker *docker.Docker, autoOidcLogin bool) *Handlers {
	return &Handlers{
		Config:        handlersConfig,
		Auth:          auth,
		Hooks:         hooks,
		Providers:     providers,
		Docker:        docker,
		AutoOidcLogin: autoOidcLogin,
	}
}

type Handlers struct {
	Config        types.HandlersConfig
	Auth          *auth.Auth
	Hooks         *hooks.Hooks
	Providers     *providers.Providers
	Docker        *docker.Docker
	AutoOidcLogin bool
}

func (h *Handlers) AuthHandler(c *gin.Context) {
	// --- Bind Proxy URI ---
	var proxy types.Proxy
	err := c.BindUri(&proxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind proxy URI")
		c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Bad Request"})
		return
	}
	log.Debug().Str("proxy", proxy.Proxy).Msg("Determined proxy type")

	// --- Check if Browser ---
	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")
	if isBrowser {
		log.Debug().Msg("Request likely from browser")
	} else {
		log.Debug().Msg("Request likely not from browser")
	}

	// --- Get Forwarded Headers ---
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")
	log.Debug().Str("host", host).Str("uri", uri).Str("proto", proto).Msg("Forwarded headers")

	// Get App ID *before* checking login status
	appId := strings.Split(host, ".")[0]
	log.Debug().Str("appId", appId).Msg("Determined App ID from host")

	// --- Fetch Labels Once ---
	labels, err := h.Docker.GetLabels(appId)
	if err != nil {
		log.Error().Err(err).Str("appId", appId).Msg("Failed to get docker labels for app")
		// Handle error appropriately (e.g., return 500 or default deny)
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error retrieving app config"})
		} else {
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=label_fetch", h.Config.AppURL))
		}
		return
	}
	log.Debug().Interface("labels", labels).Msg("Fetched labels for app")
	// --- End Fetch Labels Once ---

	// Check if auth is enabled for this request path (using tinyauth.allowed label if present)
	authEnabled, err := h.Auth.AuthEnabled(c) // This function uses headers, not labels directly
	if err != nil {
		log.Error().Err(err).Str("appId", appId).Msg("Failed check if auth is enabled for path")
		// Handle error
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error checking auth status"})
		} else {
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=auth_check", h.Config.AppURL))
		}
		return
	}

	if !authEnabled {
		log.Info().Str("uri", uri).Str("appId", appId).Msg("Auth disabled for this path based on tinyauth.allowed label")
		// Auth not required for this path, pass through (setting headers from labels)
		for key, value := range labels.Headers { // Use already fetched labels
			log.Debug().Str("key", key).Str("value", value).Msg("Setting label header (auth disabled)")
			c.Header(key, value)
		}
		c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Authenticated (Auth Disabled)"})
		return
	}
	log.Debug().Str("uri", uri).Str("appId", appId).Msg("Auth enabled for this path")

	// Auth is required, get user context
	userContext := h.Hooks.UseUserContext(c)

	if userContext.IsLoggedIn {
		log.Debug().Str("username", userContext.Username).Msg("User is logged in, checking resource access")

		// --- Call Modified ResourceAllowed ---
		appAllowed, err := h.Auth.ResourceAllowed(userContext, labels) // Pass fetched labels
		// --- End Call Modified ResourceAllowed ---

		if err != nil { // Check for actual errors from ResourceAllowed if any are added later
			log.Error().Err(err).Str("appId", appId).Msg("Error checking resource access")
			// Handle error
			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error checking permissions"})
			} else {
				c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=permission_check", h.Config.AppURL))
			}
			return
		}

		// Log the result before the check
		log.Debug().Bool("appAllowed", appAllowed).Msg("Resource allowed check result")

		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed for this resource (failed whitelist or group check)")
			// Set WWW-Authenticate header for 401
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
			} else {
				// Build query for unauthorized page
				queries, queryErr := query.Values(types.UnauthorizedQuery{
					Username: userContext.Username,
					Resource: appId, // Use appId as the resource name
				})
				if queryErr != nil {
					log.Error().Err(queryErr).Msg("Failed to build unauthorized query params")
					c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=unauth_query", h.Config.AppURL))
				} else {
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
				}
			}
			return
		}

		// User is allowed, set headers
		log.Info().Str("username", userContext.Username).Str("appId", appId).Msg("Access granted")

		// Set specific X-Remote-* headers based on claims
		if userContext.Claims != nil {
			log.Debug().Msg("Setting specific headers from claims")

			// Helper function to safely get string claim
			getStringClaim := func(key string) string {
				if val, ok := userContext.Claims[key]; ok {
					if strVal, ok := val.(string); ok {
						return strVal
					}
					return fmt.Sprintf("%v", val)
				}
				return ""
			}

			// Set X-Remote-User from preferred_username
			preferredUsername := getStringClaim("preferred_username")
			if preferredUsername != "" {
				c.Header("X-Remote-User", preferredUsername)
			}

			// Set X-Remote-Name from given_name and family_name (or fallback to name)
			givenName := getStringClaim("given_name")
			familyName := getStringClaim("family_name")
			fullName := strings.TrimSpace(givenName + " " + familyName)
			if fullName != "" {
				c.Header("X-Remote-Name", fullName)
			} else {
				nameClaim := getStringClaim("name")
				if nameClaim != "" {
					c.Header("X-Remote-Name", nameClaim)
				}
			}

			// Set X-Remote-Email from email
			email := getStringClaim("email")
			if email != "" {
				c.Header("X-Remote-Email", email)
			}

			// Set X-Remote-Groups from groups claim
			if groupsVal, ok := userContext.Claims["groups"]; ok {
				if groupsArray, ok := groupsVal.([]interface{}); ok {
					groupStrings := []string{}
					for _, group := range groupsArray {
						if groupStr, ok := group.(string); ok {
							groupStrings = append(groupStrings, groupStr)
						}
					}
					if len(groupStrings) > 0 {
						c.Header("X-Remote-Groups", strings.Join(groupStrings, ","))
					}
				}
			}
			// Add any other specific headers needed
		}

		// Set standard Remote-User (using email/sub identifier)
		log.Debug().Str("key", "Remote-User").Str("value", userContext.Username).Msg("Setting standard header")
		c.Header("Remote-User", userContext.Username)

		// Set headers from Docker labels (use fetched labels)
		for key, value := range labels.Headers {
			log.Debug().Str("key", key).Str("value", value).Msg("Setting label header")
			c.Header(key, value)
		}

		log.Debug().Msg("Authenticated and authorized, returning 200 OK")
		c.JSON(http.StatusOK, gin.H{
			"status":  http.StatusOK,
			"message": "Authenticated",
		})
		return
	}

	// User is not logged in
	log.Info().Str("appId", appId).Msg("User not logged in, denying access")
	c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
	if proxy.Proxy == "nginx" || !isBrowser {
		c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
	} else {
		// Build query for login redirect
		queries, queryErr := query.Values(types.LoginQuery{
			RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
		})
		if queryErr != nil {
			log.Error().Err(queryErr).Msg("Failed to build login redirect query params")
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=login_redirect_query", h.Config.AppURL))
		} else {
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", h.Config.AppURL, queries.Encode()))
		}
	}
}

func (h *Handlers) LoginHandler(c *gin.Context) {
	// Create login struct
	var login types.LoginRequest

	// Bind JSON
	err := c.BindJSON(&login)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Got login request")

	// Get client IP for rate limiting
	clientIP := c.ClientIP()

	// Create an identifier for rate limiting (username or IP if username doesn't exist yet)
	rateIdentifier := login.Username
	if rateIdentifier == "" {
		rateIdentifier = clientIP
	}

	// Check if the account is locked due to too many failed attempts
	locked, remainingTime := h.Auth.IsAccountLocked(rateIdentifier)
	if locked {
		log.Warn().Str("identifier", rateIdentifier).Int("remaining_seconds", remainingTime).Msg("Account is locked due to too many failed login attempts")
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	// Get user based on username
	user := h.Auth.GetUser(login.Username)

	// User does not exist
	if user == nil {
		log.Debug().Str("username", login.Username).Msg("User not found")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Got user")

	// Check if password is correct
	if !h.Auth.CheckPassword(*user, login.Password) {
		log.Debug().Str("username", login.Username).Msg("Password incorrect")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Password correct, checking totp")

	// Record successful login attempt (will reset failed attempt counter)
	h.Auth.RecordLoginAttempt(rateIdentifier, true)

	// Check if user has totp enabled
	if user.TotpSecret != "" {
		log.Debug().Msg("Totp enabled")

		// Set totp pending cookie
		h.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username:    login.Username,
			Provider:    "username",
			TotpPending: true,
		})

		// Return totp required
		c.JSON(200, gin.H{
			"status":      200,
			"message":     "Waiting for totp",
			"totpPending": true,
		})

		// Stop further processing
		return
	}

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: login.Username,
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":      200,
		"message":     "Logged in",
		"totpPending": false,
	})
}

func (h *Handlers) TotpHandler(c *gin.Context) {
	// Create totp struct
	var totpReq types.TotpRequest

	// Bind JSON
	err := c.BindJSON(&totpReq)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Checking totp")

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// Check if we have a user
	if userContext.Username == "" {
		log.Debug().Msg("No user context")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Get user
	user := h.Auth.GetUser(userContext.Username)

	// Check if user exists
	if user == nil {
		log.Debug().Msg("User not found")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Check if totp is correct
	ok := totp.Validate(totpReq.Code, user.TotpSecret)

	// TOTP is incorrect
	if !ok {
		log.Debug().Msg("Totp incorrect")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Totp correct")

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: user.Username,
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged in",
	})
}

func (h *Handlers) LogoutHandler(c *gin.Context) {
	log.Debug().Msg("Logging out")

	// Delete session cookie
	h.Auth.DeleteSessionCookie(c)

	log.Debug().Msg("Cleaning up redirect cookie")

	// Return logged out
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged out",
	})
}

func (h *Handlers) AppHandler(c *gin.Context) {
	log.Debug().Msg("Getting app context")

	// Get configured providers
	configuredProviders := h.Providers.GetConfiguredProviders()

	// We have username/password configured so add it to our providers
	if h.Auth.UserAuthConfigured() {
		configuredProviders = append(configuredProviders, "username")
	}

	// Create app context struct
	appContext := types.AppContext{
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       h.Config.DisableContinue,
		AutoOidcLogin:         h.AutoOidcLogin,
		Title:                 h.Config.Title,
		GenericName:           h.Config.GenericName,
		Domain:                h.Config.Domain,
		ForgotPasswordMessage: h.Config.ForgotPasswordMessage,
	}

	// Return app context
	c.JSON(200, appContext)
}

func (h *Handlers) UserHandler(c *gin.Context) {
	log.Debug().Msg("Getting user context")

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// Create user context response
	userContextResponse := types.UserContextResponse{
		Status:      200,
		IsLoggedIn:  userContext.IsLoggedIn,
		Username:    userContext.Username,
		Provider:    userContext.Provider,
		Oauth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// If we are not logged in we set the status to 401 and add the WWW-Authenticate header else we set it to 200
	if !userContext.IsLoggedIn {
		log.Debug().Msg("Unauthorized")
		c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
		userContextResponse.Message = "Unauthorized"
	} else {
		log.Debug().Interface("userContext", userContext).Msg("Authenticated")
		userContextResponse.Message = "Authenticated"
	}

	// Return user context
	c.JSON(200, userContextResponse)
}

func (h *Handlers) OauthUrlHandler(c *gin.Context) {
	// Create struct for OAuth request
	var request types.OAuthRequest

	// Bind URI
	err := c.BindUri(&request)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Got OAuth request")

	// Check if provider exists
	provider := h.Providers.GetProvider(request.Provider)

	// Provider does not exist
	if provider == nil {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	log.Debug().Str("provider", request.Provider).Msg("Got provider")

	// Create state
	state := provider.GenerateState()

	// Get auth URL
	authURL := provider.GetAuthURL(state)

	log.Debug().Msg("Got auth URL")

	// Set CSRF cookie
	c.SetCookie("tinyauth-csrf", state, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)

	// Get redirect URI
	redirectURI := c.Query("redirect_uri")

	// Set redirect cookie if redirect URI is provided
	if redirectURI != "" {
		log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
		c.SetCookie("tinyauth-redirect", redirectURI, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)
	}

	// Return auth URL
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authURL,
	})
}

func (h *Handlers) OauthCallbackHandler(c *gin.Context) {
	var providerName types.OAuthRequest
	err := c.BindUri(&providerName)
	if err != nil {
		// ... (error handling) ...
		return
	}
	log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name for callback")

	state := c.Query("state")
	csrfCookie, err := c.Cookie("tinyauth-csrf")
	if err != nil || csrfCookie != state {
		log.Warn().Msg("Invalid or missing CSRF cookie/state mismatch")
		c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up bad cookie
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=csrf", h.Config.AppURL))
		return
	}
	c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up valid CSRF cookie

	code := c.Query("code")
	log.Debug().Msg("Got authorization code")

	provider := h.Providers.GetProvider(providerName.Provider)
	if provider == nil {
		log.Error().Str("provider", providerName.Provider).Msg("Provider not found during callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=provider_not_found", h.Config.AppURL))
		return
	}

	// --- MODIFY ExchangeToken CALL ---
	// Call the modified ExchangeToken which returns the full token
	token, err := provider.ExchangeToken(code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=token_exchange", h.Config.AppURL))
		return
	}
	log.Debug().Msg("Exchanged token successfully")

	// --- MODIFY GetUser CALL ---
	// Call the modified GetUser, passing the full token
	identifier, claims, err := h.Providers.GetUser(providerName.Provider, token)
	if err != nil {
		log.Error().Err(err).Str("provider", providerName.Provider).Msg("Failed to get user info")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=user_info", h.Config.AppURL))
		return
	}
	log.Debug().Str("identifier", identifier).Interface("claims", claims).Msg("Got user info")

	// Check whitelist using the identifier (email or sub)
	if !h.Auth.EmailWhitelisted(identifier) {
		log.Warn().Str("identifier", identifier).Msg("Identifier not whitelisted")
		queries, _ := query.Values(types.UnauthorizedQuery{Username: identifier}) // Use identifier here
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
		return // Stop processing
	}
	log.Debug().Msg("Identifier whitelisted")

	// --- MODIFY CreateSessionCookie CALL ---
	// Create session cookie, passing the identifier and the claims map
	err = h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: identifier, // Use the identifier (email/sub)
		Provider: providerName.Provider,
		Claims:   claims, // Pass the claims map here
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session cookie after OAuth callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=session_creation", h.Config.AppURL))
		return
	}

	// --- Redirect logic remains the same ---
	redirectCookie, err := c.Cookie("tinyauth-redirect")
	if err != nil {
		log.Debug().Msg("No redirect cookie, redirecting to AppURL")
		c.Redirect(http.StatusPermanentRedirect, h.Config.AppURL)
		return
	}
	log.Debug().Str("redirectURI", redirectCookie).Msg("Got redirect URI from cookie")

	queries, err := query.Values(types.LoginQuery{RedirectURI: redirectCookie})
	if err != nil {
		log.Error().Err(err).Msg("Failed to build redirect query")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=redirect_query", h.Config.AppURL))
		return
	}

	c.SetCookie("tinyauth-redirect", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up redirect cookie
	c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
