package hooks

import (
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func NewHooks(auth *auth.Auth, providers *providers.Providers) *Hooks {
	return &Hooks{
		Auth:      auth,
		Providers: providers,
	}
}

type Hooks struct {
	Auth      *auth.Auth
	Providers *providers.Providers
}

func (hooks *Hooks) UseUserContext(c *gin.Context) types.UserContext {
    // Get session cookie (which now includes Email, Name, PreferredUsername)
    cookie, err := hooks.Auth.GetSessionCookie(c)
    basic := hooks.Auth.GetBasicAuth(c)

    var userGroups []string
    if cookie.Groups != "" {
        userGroups = strings.Split(cookie.Groups, ",")
        for i, group := range userGroups { userGroups[i] = strings.TrimSpace(group) }
         cleanedGroups := make([]string, 0, len(userGroups))
        for _, group := range userGroups { if group != "" { cleanedGroups = append(cleanedGroups, group) } }
        userGroups = cleanedGroups
    }

    // --- Basic Auth ---
    if basic != nil {
        user := hooks.Auth.GetUser(basic.Username)
        if user != nil && hooks.Auth.CheckPassword(*user, basic.Password) {
            return types.UserContext{
                Username:    basic.Username,
                IsLoggedIn:  true, Provider: "basic",
                // No OIDC fields for basic auth
            }
        }
    }

    // --- Cookie Check ---
    if err != nil || cookie.Username == "" { 
        return types.UserContext{IsLoggedIn: false}
    }

    if cookie.TotpPending { // Handle TOTP pending
        return types.UserContext{
            Username:    cookie.Username, Provider: cookie.Provider, TotpPending: true,
            Email: cookie.Email, Name: cookie.Name, PreferredUsername: cookie.PreferredUsername, Groups: userGroups,
        }
    }

    if cookie.Provider == "username" {
        if hooks.Auth.GetUser(cookie.Username) != nil {
            return types.UserContext{
                Username: cookie.Username, IsLoggedIn: true, Provider: "username",
            }
        }
    }

    // --- OAuth User ---
    provider := hooks.Providers.GetProvider(cookie.Provider)
    if provider != nil {
        // Optional: Re-check whitelist if needed, otherwise remove if group check is sufficient
        if !hooks.Auth.EmailWhitelisted(cookie.Username) { 
             log.Warn().Str("username", cookie.Username).Msg("OAuth user session exists but identifier is not whitelisted.")
             hooks.Auth.DeleteSessionCookie(c)
            return types.UserContext{IsLoggedIn: false}
        }

        // Return fully populated context for OAuth user
        return types.UserContext{
            Username:            cookie.Username,
            IsLoggedIn:          true,
            OAuth:               true,
            Provider:            cookie.Provider,
            TotpPending:         false,
            Groups:              userGroups,
            Email:               cookie.Email,
            Name:                cookie.Name, 
            PreferredUsername:   cookie.PreferredUsername,
        }
    }

    // Default empty context
    log.Warn().Str("cookieUsername", cookie.Username).Str("cookieProvider", cookie.Provider).Msg("Cookie found but provider invalid or user no longer valid.")
    return types.UserContext{IsLoggedIn: false}
}
