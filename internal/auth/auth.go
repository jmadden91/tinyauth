package auth

import (
	"encoding/gob"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// ADD GOB REGISTRATION FOR THE CLAIMS MAP TYPE
func init() {
	gob.Register(map[string]interface{}{})
}

func NewAuth(config types.AuthConfig, docker *docker.Docker) *Auth {
	return &Auth{
		Config:        config,
		Docker:        docker,
		LoginAttempts: make(map[string]*types.LoginAttempt),
	}
}

type Auth struct {
	Config        types.AuthConfig
	Docker        *docker.Docker
	LoginAttempts map[string]*types.LoginAttempt
	LoginMutex    sync.RWMutex
}

func (auth *Auth) GetSession(c *gin.Context) (*sessions.Session, error) {
	// Create cookie store
	store := sessions.NewCookieStore([]byte(auth.Config.Secret))

	// Configure cookie store
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   auth.Config.SessionExpiry,
		Secure:   auth.Config.CookieSecure,
		HttpOnly: true,
		Domain:   fmt.Sprintf(".%s", auth.Config.Domain),
	}

	// Get session
	session, err := store.Get(c.Request, "tinyauth")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return nil, err
	}

	return session, nil
}

func (auth *Auth) GetUser(username string) *types.User {
	// Loop through users and return the user if the username matches
	for _, user := range auth.Config.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *Auth) CheckPassword(user types.User, password string) bool {
	// Compare the hashed password with the password provided
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

// IsAccountLocked checks if a username or IP is locked due to too many failed login attempts
func (auth *Auth) IsAccountLocked(identifier string) (bool, int) {
	auth.LoginMutex.RLock()
	defer auth.LoginMutex.RUnlock()

	// Return false if rate limiting is not configured
	if auth.Config.LoginMaxRetries <= 0 || auth.Config.LoginTimeout <= 0 {
		return false, 0
	}

	// Check if the identifier exists in the map
	attempt, exists := auth.LoginAttempts[identifier]
	if !exists {
		return false, 0
	}

	// If account is locked, check if lock time has expired
	if attempt.LockedUntil.After(time.Now()) {
		// Calculate remaining lockout time in seconds
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}

	// Lock has expired
	return false, 0
}

// RecordLoginAttempt records a login attempt for rate limiting
func (auth *Auth) RecordLoginAttempt(identifier string, success bool) {
	// Skip if rate limiting is not configured
	if auth.Config.LoginMaxRetries <= 0 || auth.Config.LoginTimeout <= 0 {
		return
	}

	auth.LoginMutex.Lock()
	defer auth.LoginMutex.Unlock()

	// Get current attempt record or create a new one
	attempt, exists := auth.LoginAttempts[identifier]
	if !exists {
		attempt = &types.LoginAttempt{}
		auth.LoginAttempts[identifier] = attempt
	}

	// Update last attempt time
	attempt.LastAttempt = time.Now()

	// If successful login, reset failed attempts
	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}

	// Increment failed attempts
	attempt.FailedAttempts++

	// If max retries reached, lock the account
	if attempt.FailedAttempts >= auth.Config.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.Config.LoginTimeout) * time.Second)
		log.Warn().Str("identifier", identifier).Int("timeout", auth.Config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	return utils.CheckWhitelist(auth.Config.OauthWhitelist, emailSrc)
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) error {
	log.Debug().Msg("Creating session cookie")

	// Get session
	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return err
	}

	log.Debug().Msg("Setting session cookie values")

	// Calculate expiry
	var sessionExpiry int
	if data.TotpPending {
		sessionExpiry = 3600 // Shorter expiry for pending TOTP
	} else {
		sessionExpiry = auth.Config.SessionExpiry
	}

	// Set data
	session.Values["username"] = data.Username
	session.Values["provider"] = data.Provider
	session.Values["expiry"] = time.Now().Add(time.Duration(sessionExpiry) * time.Second).Unix()
	session.Values["totpPending"] = data.TotpPending
	// ADD saving claims
	if data.Claims != nil {
		session.Values["claims"] = data.Claims
		log.Debug().Interface("claims", data.Claims).Msg("Adding claims to session")
	} else {
		// Ensure claims field is removed if not provided
		delete(session.Values, "claims")
	}

	// Save session
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		log.Error().Err(err).Msg("Failed to save session")
		return err
	}

	log.Debug().Msg("Session cookie created/updated")
	return nil
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) error {
	log.Debug().Msg("Deleting session cookie")

	// Get session
	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return err
	}

	// Delete all values in the session
	for key := range session.Values {
		delete(session.Values, key)
	}

	// Save session
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		log.Error().Err(err).Msg("Failed to save session")
		return err
	}

	// Return nil
	return nil
}

func (auth *Auth) GetSessionCookie(c *gin.Context) (types.SessionCookie, error) {
	log.Debug().Msg("Getting session cookie")

	// Get session
	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return types.SessionCookie{}, err
	}

	// Get core data from session
	username, usernameOk := session.Values["username"].(string)
	provider, providerOK := session.Values["provider"].(string)
	expiry, expiryOk := session.Values["expiry"].(int64)
	totpPending, totpPendingOk := session.Values["totpPending"].(bool)

	// Basic check for essential fields
	if !usernameOk || !providerOK || !expiryOk || !totpPendingOk {
		log.Warn().Msg("Session cookie is missing essential data")
		// Clear potentially inconsistent session
		auth.DeleteSessionCookie(c)
		return types.SessionCookie{}, nil
	}

	// Check if the cookie has expired
	if time.Now().Unix() > expiry {
		log.Warn().Msg("Session cookie expired")
		auth.DeleteSessionCookie(c)
		return types.SessionCookie{}, nil
	}

	// --- ADD retrieving claims ---
	var claims map[string]interface{}
	claimsInterface, claimsOk := session.Values["claims"]
	if claimsOk && claimsInterface != nil {
		// Perform type assertion
		claims, claimsOk = claimsInterface.(map[string]interface{})
		if !claimsOk {
			log.Warn().Msg("Session cookie 'claims' field is not of type map[string]interface{}")
			// Optionally clear the session if claims are corrupted
			// auth.DeleteSessionCookie(c)
			// return types.SessionCookie{}, errors.New("corrupted claims data in session")
			claims = nil // Treat as if claims are not present
		}
	} else {
		// Claims not present or nil, which is fine
		claims = nil
	}
	// --- END retrieving claims ---


	log.Debug().
		Str("username", username).
		Str("provider", provider).
		Int64("expiry", expiry).
		Bool("totpPending", totpPending).
		Interface("claims", claims). // Log claims for debugging
		Msg("Parsed cookie")

	// Return the cookie
	return types.SessionCookie{
		Username:    username,
		Provider:    provider,
		TotpPending: totpPending,
		Claims:      claims, // Add claims here
	}, nil
}

func (auth *Auth) UserAuthConfigured() bool {
	// If there are users, return true
	return len(auth.Config.Users) > 0
}

func (auth *Auth) ResourceAllowed(c *gin.Context, context types.UserContext) (bool, error) {
	// Get headers
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Get app id
	appId := strings.Split(host, ".")[0]

	// Get the container labels
	labels, err := auth.Docker.GetLabels(appId)

	// If there is an error, return false
	if err != nil {
		return false, err
	}

	// Check if oauth is allowed
	if context.OAuth {
		log.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckWhitelist(labels.OAuthWhitelist, context.Username), nil
	}

	// Check users
	log.Debug().Msg("Checking users")

	return utils.CheckWhitelist(labels.Users, context.Username), nil
}

func (auth *Auth) AuthEnabled(c *gin.Context) (bool, error) {
	// Get headers
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Get app id
	appId := strings.Split(host, ".")[0]

	// Get the container labels
	labels, err := auth.Docker.GetLabels(appId)

	// If there is an error, auth enabled
	if err != nil {
		return true, err
	}

	// Check if the allowed label is empty
	if labels.Allowed == "" {
		// Auth enabled
		return true, nil
	}

	// Compile regex
	regex, err := regexp.Compile(labels.Allowed)

	// If there is an error, invalid regex, auth enabled
	if err != nil {
		log.Warn().Err(err).Msg("Invalid regex")
		return true, err
	}

	// Check if the uri matches the regex
	if regex.MatchString(uri) {
		// Auth disabled
		return false, nil
	}

	// Auth enabled
	return true, nil
}

func (auth *Auth) GetBasicAuth(c *gin.Context) *types.User {
	// Get the Authorization header
	username, password, ok := c.Request.BasicAuth()

	// If not ok, return an empty user
	if !ok {
		return nil
	}

	// Return the user
	return &types.User{
		Username: username,
		Password: password,
	}
}
