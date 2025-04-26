package handlers

import (
	"errors"
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

// Your NewHandlers function (preserved)
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

// Your Handlers struct (preserved)
type Handlers struct {
	Config        types.HandlersConfig
	Auth          *auth.Auth
	Hooks         *hooks.Hooks
	Providers     *providers.Providers
	Docker        *docker.Docker
	AutoOidcLogin bool
}

// Your AuthHandler function (preserved from previous correction)
func (h *Handlers) AuthHandler(c *gin.Context) {
	var proxy types.Proxy
	err := c.BindUri(&proxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind proxy URI")
		c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Bad Request"})
		return
	}
	log.Debug().Str("proxy", proxy.Proxy).Msg("Determined proxy type")

	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")
	if isBrowser { log.Debug().Msg("Request likely from browser") } else { log.Debug().Msg("Request likely not from browser") }

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")
	log.Debug().Str("host", host).Str("uri", uri).Str("proto", proto).Msg("Forwarded headers")

	groupsHeader := c.Request.Header.Get("X-Remote-Groups")
	log.Debug().Str("groups", groupsHeader).Msg("Read incoming X-Remote-Groups header (expected empty on check)")

	appId := strings.Split(host, ".")[0]
	log.Debug().Str("appId", appId).Msg("Determined App ID from host")

	labels, err := h.Docker.GetLabels(appId)
	if err != nil {
		log.Error().Err(err).Str("appId", appId).Msg("Failed to get docker labels for app")
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error retrieving app config"})
		} else {
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=label_fetch", h.Config.AppURL))
		}
		return
	}
	log.Debug().Interface("labels", labels).Msg("Fetched labels for app")

	authEnabled, err := h.Auth.AuthEnabled(c)
	if err != nil {
		log.Error().Err(err).Str("appId", appId).Msg("Failed check if auth is enabled for path")
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error checking auth status"})
		} else {
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=auth_check", h.Config.AppURL))
		}
		return
	}

	if !authEnabled {
		log.Info().Str("uri", uri).Str("appId", appId).Msg("Auth disabled for this path based on tinyauth.allowed label")
		for key, value := range labels.Headers { log.Debug().Str("key", key).Str("value", value).Msg("Setting label header (auth disabled)"); c.Header(key, value) }
		c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Authenticated (Auth Disabled)"})
		return
	}
	log.Debug().Str("uri", uri).Str("appId", appId).Msg("Auth enabled for this path")

	userContext := h.Hooks.UseUserContext(c)

	if userContext.IsLoggedIn {
		log.Debug().Str("username", userContext.Username).Msg("User is logged in, checking resource access")

		// Call ResourceAllowed WITHOUT groupsHeader argument
		appAllowed, err := h.Auth.ResourceAllowed(c, userContext)

		if err != nil {
			log.Error().Err(err).Str("appId", appId).Msg("Error checking resource access")
			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error checking permissions"})
			} else {
				c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=permission_check", h.Config.AppURL))
			}
			return
		}

		log.Debug().Bool("appAllowed", appAllowed).Msg("Resource allowed check result")

		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed for this resource (failed group check)")
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
			} else {
				queries, queryErr := query.Values(types.UnauthorizedQuery{ Username: userContext.Username, Resource: appId })
				if queryErr != nil {
					log.Error().Err(queryErr).Msg("Failed to build unauthorized query params")
					c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=unauth_query", h.Config.AppURL))
				} else {
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
				}
			}
			return
		}

		// --- Access Granted Path ---
		log.Info().Str("username", userContext.Username).Str("appId", appId).Msg("Access granted")

		// --- Set Headers ---
		remoteUser := userContext.PreferredUsername
		if remoteUser == "" { remoteUser = userContext.Username }
		log.Debug().Str("key", "X-Remote-User").Str("value", remoteUser).Msg("Setting X-Remote-User header"); c.Header("X-Remote-User", remoteUser)
		if userContext.Name != "" { log.Debug().Str("key", "X-Remote-Name").Str("value", userContext.Name).Msg("Setting X-Remote-Name header"); c.Header("X-Remote-Name", userContext.Name) }
		if userContext.Email != "" { log.Debug().Str("key", "X-Remote-Email").Str("value", userContext.Email).Msg("Setting X-Remote-Email header"); c.Header("X-Remote-Email", userContext.Email) }
		if len(userContext.Groups) > 0 { groupsValue := strings.Join(userContext.Groups, ","); log.Debug().Str("key", "X-Remote-Groups").Str("value", groupsValue).Msg("Setting groups header from user context"); c.Header("X-Remote-Groups", groupsValue) }
		log.Debug().Str("key", "Remote-User").Str("value", userContext.Username).Msg("Setting standard Remote-User header"); c.Header("Remote-User", userContext.Username)
		for key, value := range labels.Headers { log.Debug().Str("key", key).Str("value", value).Msg("Setting label header"); c.Header(key, value) }

		log.Debug().Msg("Authenticated and authorized, returning 200 OK to proxy")
		c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Authenticated"})
		return
	}

	// User is not logged in
	log.Info().Str("appId", appId).Msg("User not logged in, denying access")
	c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
	if proxy.Proxy == "nginx" || !isBrowser {
		c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
	} else {
		queries, queryErr := query.Values(types.LoginQuery{ RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri) })
		if queryErr != nil {
			log.Error().Err(queryErr).Msg("Failed to build login redirect query params")
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=login_redirect_query", h.Config.AppURL))
		} else {
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", h.Config.AppURL, queries.Encode()))
		}
	}
}

// LoginHandler (Seems OK from your file, included for completeness)
func (h *Handlers) LoginHandler(c *gin.Context) {
    var login types.LoginRequest
    err := c.BindJSON(&login)
    if err != nil {
        log.Error().Err(err).Msg("Failed to bind JSON")
        c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Bad Request"})
        return
    }
    log.Debug().Msg("Got login request")

    clientIP := c.ClientIP()
    rateIdentifier := login.Username
    if rateIdentifier == "" { rateIdentifier = clientIP }

    locked, remainingTime := h.Auth.IsAccountLocked(rateIdentifier)
    if locked {
        log.Warn().Str("identifier", rateIdentifier).Int("remaining_seconds", remainingTime).Msg("Account is locked")
        c.JSON(http.StatusTooManyRequests, gin.H{"status": http.StatusTooManyRequests, "message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime)})
        return
    }

    user := h.Auth.GetUser(login.Username)
    if user == nil {
        log.Debug().Str("username", login.Username).Msg("User not found")
        h.Auth.RecordLoginAttempt(rateIdentifier, false)
        c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
        return
    }
    log.Debug().Msg("Got user")

    if !h.Auth.CheckPassword(*user, login.Password) {
        log.Debug().Str("username", login.Username).Msg("Password incorrect")
        h.Auth.RecordLoginAttempt(rateIdentifier, false)
        c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
        return
    }
    log.Debug().Msg("Password correct, checking totp")
    h.Auth.RecordLoginAttempt(rateIdentifier, true)

    if user.TotpSecret != "" {
        log.Debug().Msg("Totp enabled")
        err = h.Auth.CreateSessionCookie(c, &types.SessionCookie{
            Username:    login.Username,
            Provider:    "username",
            TotpPending: true,
        })
         if err != nil {
            log.Error().Err(err).Msg("Failed to create TOTP pending session cookie")
            c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Waiting for totp", "totpPending": true})
        return
    }

    err = h.Auth.CreateSessionCookie(c, &types.SessionCookie{
        Username: login.Username,
        Provider: "username",
    })
     if err != nil {
        log.Error().Err(err).Msg("Failed to create session cookie")
        c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Logged in", "totpPending": false})
}

// TotpHandler (Seems OK from your file, included for completeness)
func (h *Handlers) TotpHandler(c *gin.Context) {
    var totpReq types.TotpRequest
    err := c.BindJSON(&totpReq)
    if err != nil {
        log.Error().Err(err).Msg("Failed to bind JSON")
        c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Bad Request"})
        return
    }
    log.Debug().Msg("Checking totp")

    userContext := h.Hooks.UseUserContext(c)
    if userContext.Username == "" || !userContext.TotpPending {
        log.Debug().Msg("No user context or TOTP not pending")
        c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
        return
    }

    user := h.Auth.GetUser(userContext.Username)
    if user == nil {
        log.Debug().Msg("User not found")
        c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
        return
    }
     if user.TotpSecret == "" {
        log.Warn().Str("username", user.Username).Msg("TOTP verification attempted for user without TOTP configured")
        c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "TOTP not configured"})
        return
    }

    ok := totp.Validate(totpReq.Code, user.TotpSecret)
    if !ok {
        log.Debug().Msg("Totp incorrect")
        c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Unauthorized"})
        return
    }
    log.Debug().Msg("Totp correct")

    err = h.Auth.CreateSessionCookie(c, &types.SessionCookie{
        Username: user.Username,
        Provider: "username",
        TotpPending: false,
    })
     if err != nil {
        log.Error().Err(err).Msg("Failed to create session cookie after TOTP verification")
        c.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "message": "Internal Server Error"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Logged in"})
}

// LogoutHandler (Seems OK from your file, included for completeness)
func (h *Handlers) LogoutHandler(c *gin.Context) {
    log.Debug().Msg("Logging out")
    err := h.Auth.DeleteSessionCookie(c)
    if err != nil {
         log.Error().Err(err).Msg("Error deleting session cookie during logout")
    }
    c.SetCookie("tinyauth-redirect", "", -1, "/", "", h.Config.CookieSecure, true)
    log.Debug().Msg("Logout complete")
    c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Logged out"})
}

// AppHandler (Seems OK from your file, included for completeness)
func (h *Handlers) AppHandler(c *gin.Context) {
    log.Debug().Msg("Getting app context")
    configuredProviders := h.Providers.GetConfiguredProviders()
    if h.Auth.UserAuthConfigured() {
        configuredProviders = append(configuredProviders, "username")
    }
    appContext := types.AppContext{
        Status:                http.StatusOK,
        Message:               "OK",
        ConfiguredProviders:   configuredProviders,
        DisableContinue:       h.Config.DisableContinue,
        AutoOidcLogin:         h.AutoOidcLogin,
        Title:                 h.Config.Title,
        GenericName:           h.Config.GenericName,
        Domain:                h.Config.Domain,
        ForgotPasswordMessage: h.Config.ForgotPasswordMessage,
    }
    c.JSON(http.StatusOK, appContext)
}

// UserHandler (Seems OK from your file, included for completeness)
func (h *Handlers) UserHandler(c *gin.Context) {
    log.Debug().Msg("Getting user context")
    userContext := h.Hooks.UseUserContext(c)
    userContextResponse := types.UserContextResponse{
        Status:      http.StatusOK,
        IsLoggedIn:  userContext.IsLoggedIn,
        Username:    userContext.Username,
        Provider:    userContext.Provider,
        Oauth:       userContext.OAuth,
        TotpPending: userContext.TotpPending,
        Message:     "Authenticated",
    }
    if !userContext.IsLoggedIn {
        log.Debug().Msg("User context indicates not logged in")
        c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
        userContextResponse.Message = "Unauthorized"
    } else {
        log.Debug().Interface("userContext", userContext).Msg("User context indicates authenticated")
    }
    c.JSON(http.StatusOK, userContextResponse)
}

// OauthUrlHandler (Seems OK from your file, included for completeness)
func (h *Handlers) OauthUrlHandler(c *gin.Context) {
    var request types.OAuthRequest
    err := c.BindUri(&request)
    if err != nil {
        log.Error().Err(err).Msg("Failed to bind OAuth provider URI")
        c.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Bad Request"})
        return
    }
    log.Debug().Str("provider", request.Provider).Msg("Got OAuth URL request")

    provider := h.Providers.GetProvider(request.Provider)
    if provider == nil {
         log.Warn().Str("provider", request.Provider).Msg("Requested OAuth provider not found or configured")
        c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "Provider Not Found"})
        return
    }

    state := provider.GenerateState()
    authURL := provider.GetAuthURL(state)
    log.Debug().Str("provider", request.Provider).Msg("Generated auth URL")

    c.SetCookie("tinyauth-csrf", state, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)

    redirectURI := c.Query("redirect_uri")
    if redirectURI != "" {
        log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie for OAuth flow")
        c.SetCookie("tinyauth-redirect", redirectURI, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)
    }

    c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "OK", "url": authURL})
}

// --- CORRECTED OauthCallbackHandler ---
func (h *Handlers) OauthCallbackHandler(c *gin.Context) {
	// Provider name from URI
	var providerUriData types.OAuthRequest // Declare variable to hold URI data
	err := c.BindUri(&providerUriData)     // Use := for first declaration
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind provider name from URI")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=invalid_provider_uri", h.Config.AppURL))
		return
	}
	log.Debug().Str("provider", providerUriData.Provider).Msg("Got provider name from URI")

	// --- CSRF Check ---
	state := c.Query("state")
	csrfCookie, err := c.Cookie("tinyauth-csrf") // Use = as err is declared above
	if err != nil {
		log.Warn().Msg("No CSRF cookie found during OAuth callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=csrf_missing", h.Config.AppURL))
		return
	}
	c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up immediately

	if csrfCookie != state {
		log.Warn().Str("state", state).Str("cookie", csrfCookie).Msg("Invalid CSRF cookie or state mismatch")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=csrf_mismatch", h.Config.AppURL))
		return
	}
	log.Debug().Msg("CSRF check passed")

	// --- Token Exchange ---
	code := c.Query("code") // Define code here
	if code == "" {
		log.Error().Msg("Missing authorization code in OAuth callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=code_missing", h.Config.AppURL))
		return
	}
	log.Debug().Msg("Got authorization code")

	// Define provider instance here
	provider := h.Providers.GetProvider(providerUriData.Provider)
	if provider == nil {
		log.Error().Str("provider", providerUriData.Provider).Msg("OAuth provider instance not found or not configured")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=provider_not_found", h.Config.AppURL))
		return
	}

	// Exchange token - use = for err as it was declared above
	_, err = provider.ExchangeToken(code)
	if err != nil {
		log.Error().Err(err).Str("provider", providerUriData.Provider).Msg("Failed to exchange OAuth token")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=token_exchange", h.Config.AppURL))
		return
	}
	log.Debug().Msg("OAuth token exchanged successfully")

	// --- Get User Info ---
	var userInfo providers.GenericUserInfoResponse
	var fetchErr error // Use different error variable for clarity

	switch providerUriData.Provider {
	case "generic":
		if h.Providers.Generic != nil {
			client := h.Providers.Generic.GetClient()
			userInfo, fetchErr = providers.GetGenericUserInfo(client, h.Providers.Config.GenericUserURL)
		} else {
			fetchErr = errors.New("generic provider not configured")
		}
	// Add other provider cases here if needed
	default:
		fetchErr = fmt.Errorf("unsupported provider type for fetching user info: %s", providerUriData.Provider)
	}

	if fetchErr != nil {
		log.Error().Err(fetchErr).Str("provider", providerUriData.Provider).Msg("Failed to get user info")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=userinfo_fetch", h.Config.AppURL))
		return
	}
	log.Debug().Interface("userInfo", userInfo).Msg("Got user info struct from provider")

	// --- Whitelist & Cookie Creation ---
	identifier := userInfo.Email
	if identifier == "" { identifier = userInfo.Sub }
	if identifier == "" {
		log.Error().Msg("Could not determine primary identifier (email or sub) from userinfo")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=missing_identifier", h.Config.AppURL))
		return
	}

	if !h.Auth.EmailWhitelisted(identifier) {
		log.Warn().Str("identifier", identifier).Msg("Identifier not whitelisted")
		queries, _ := query.Values(types.UnauthorizedQuery{Username: identifier})
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
		return
	}
	log.Debug().Msg("Identifier whitelisted")

	groupsString := strings.Join(userInfo.Groups, ",")

	cookieData := &types.SessionCookie{
		Username:            identifier,
		Provider:            providerUriData.Provider,
		Groups:              groupsString,
		Email:               userInfo.Email,
		Name:                userInfo.Name,
		PreferredUsername:   userInfo.PreferredUsername,
	}

	err = h.Auth.CreateSessionCookie(c, cookieData) // Use = for err reassignment
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session cookie after OAuth callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=session_creation", h.Config.AppURL))
		return
	}
	log.Debug().Msg("Session cookie created successfully")

	// --- Redirect ---
	redirectCookie, err := c.Cookie("tinyauth-redirect") // Use =
	if err != nil {
		log.Debug().Msg("No redirect cookie found, redirecting to App URL")
		c.Redirect(http.StatusPermanentRedirect, h.Config.AppURL)
		return
	}
	c.SetCookie("tinyauth-redirect", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up

	queries, err := query.Values(types.LoginQuery{RedirectURI: redirectCookie}) // Use =
	if err != nil {
		log.Error().Err(err).Msg("Failed to build query for continue page redirect")
		c.Redirect(http.StatusPermanentRedirect, h.Config.AppURL)
		return
	}
	c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}

// HealthcheckHandler (Seems OK from your file, included for completeness)
func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "OK",
	})
}