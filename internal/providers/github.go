package providers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Github has a different response than the generic provider
type GithubUserInfoResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

// The scopes required for the github provider
func GithubScopes() []string {
	return []string{"user:email"}
}

func GetGithubEmail(client *http.Client) (string, error) {
	// Get the user emails from github using the oauth http client
	res, err := client.Get("https://api.github.com/user/emails")

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Got response from github")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Read body from github")

	// Parse the body into a user struct
	var emails GithubUserInfoResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &emails)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Parsed emails from github")

	// Find and return the primary email
	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	// User does not have a primary email?
	return "", errors.New("no primary email found")
}
