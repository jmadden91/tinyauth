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
    session, err := auth.GetSession(c)
    if err != nil { return err } // Error already logged

    log.Debug().
        Str("username", data.Username).
        Str("provider", data.Provider).
        Str("groups", data.Groups).
        Str("email", data.Email).
        Str("name", data.Name).
        Str("preferredUsername", data.PreferredUsername).
        Bool("totpPending", data.TotpPending).
        Msg("Setting session cookie values")

    var sessionExpiry int
    if data.TotpPending { sessionExpiry = 3600 } else { sessionExpiry = auth.Config.SessionExpiry }

    // Set data
    session.Values["username"] = data.Username
    session.Values["provider"] = data.Provider
    session.Values["expiry"] = time.Now().Add(time.Duration(sessionExpiry) * time.Second).Unix()
    session.Values["totpPending"] = data.TotpPending
    session.Values["groups"] = data.Groups
    session.Values["email"] = data.Email                         
    session.Values["name"] = data.Name                          
    session.Values["preferred_username"] = data.PreferredUsername

    err = session.Save(c.Request, c.Writer)
    if err != nil { log.Error().Err(err).Msg("Failed to save session"); return err }
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
    session, err := auth.GetSession(c)
    if err != nil { return types.SessionCookie{}, err }

    // Get essential data
    username, usernameOk := session.Values["username"].(string)
    provider, providerOk := session.Values["provider"].(string)
    expiry, expiryOk := session.Values["expiry"].(int64)
    totpPending, totpPendingOk := session.Values["totpPending"].(bool)

    if !usernameOk || !providerOk || !expiryOk || !totpPendingOk {
        log.Warn().Msg("Session cookie is missing essential data")
        return types.SessionCookie{}, nil
    }

    // Check expiry first
    if time.Now().Unix() > expiry {
        log.Warn().Msg("Session cookie expired")
        auth.DeleteSessionCookie(c)
        return types.SessionCookie{}, nil
    }

    // Get additional fields (handle missing fields gracefully)
    groups, _ := session.Values["groups"].(string)
    email, _ := session.Values["email"].(string)
    name, _ := session.Values["name"].(string)
    preferredUsername, _ := session.Values["preferred_username"].(string)

    log.Debug().
        Str("username", username).
        Str("provider", provider).
        Int64("expiry", expiry).
        Bool("totpPending", totpPending).
        Str("groups", groups).
        Str("email", email).
        Str("name", name).
        Str("preferredUsername", preferredUsername).
        Msg("Parsed session cookie")

    return types.SessionCookie{
        Username:            username,
        Provider:            provider,
        TotpPending:         totpPending,
        Groups:              groups,
        Email:               email,
        Name:                name,
        PreferredUsername:   preferredUsername,
    }, nil
}

func (auth *Auth) UserAuthConfigured() bool {
	// If there are users, return true
	return len(auth.Config.Users) > 0
}

func (auth *Auth) ResourceAllowed(c *gin.Context, context types.UserContext) (bool, error) {
    host := c.Request.Header.Get("X-Forwarded-Host")
    appId := strings.Split(host, ".")[0]
    labels, err := auth.Docker.GetLabels(appId)
    if err != nil {
        log.Error().Err(err).Str("appId", appId).Msg("Failed to get Docker labels for resource check")
        return false, err
    }

    // --- Group Check ---
    if labels.RequiredGroups == "" {
        log.Debug().Str("appId", appId).Str("username", context.Username).Msg("No required groups specified via label, access granted.")
        return true, nil
    }

    if len(context.Groups) == 0 {
        log.Warn().Str("appId", appId).Str("username", context.Username).Msg("Access denied: Required groups specified, but user context has no groups.")
        return false, nil
    }

    // Parse required groups
    requiredGroupsRaw := strings.Split(labels.RequiredGroups, ",")
    requiredGroups := make([]string, 0, len(requiredGroupsRaw))
    for _, rg := range requiredGroupsRaw {
        trimmed := strings.TrimSpace(rg)
        if trimmed != "" {
            requiredGroups = append(requiredGroups, trimmed)
        }
    }

     // Handle case where RequiredGroups label exists but is empty after trimming
    if len(requiredGroups) == 0 {
        log.Debug().Str("appId", appId).Str("username", context.Username).Msg("Required groups label was present but empty after trim, access granted.")
        return true, nil
    }

    // Use context.Groups directly
    userGroups := context.Groups

    log.Debug().Strs("required", requiredGroups).Strs("userHas", userGroups).Str("username", context.Username).Msg("Checking group membership using user context")

    // Check if any user group matches any required group
    groupMatch := false
    for _, userGroup := range userGroups {
        for _, reqGroup := range requiredGroups {
            // Consider strings.EqualFold(userGroup, reqGroup) for case-insensitivity
            if userGroup == reqGroup {
                groupMatch = true
                log.Debug().Str("username", context.Username).Str("matchingGroup", userGroup).Msg("Group match found.")
                break
            }
        }
        if groupMatch {
            break
        }
    }

    if !groupMatch {
        log.Warn().Str("appId", appId).Str("username", context.Username).Strs("requiredGroups", requiredGroups).Strs("userGroups", userGroups).Msg("Access denied: User does not have any of the required groups in context.")
        return false, nil
    }

    log.Debug().Str("username", context.Username).Msg("Access granted: User has a required group.")
    return true, nil
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
