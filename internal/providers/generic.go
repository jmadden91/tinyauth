package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"errors"
	"github.com/rs/zerolog/log"
)

type GenericUserInfoResponse struct {
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	PreferredUsername string   `json:"preferred_username"`
	Sub string `json:"sub"`
}

func GetGenericUserInfo(client *http.Client, url string) (userInfo GenericUserInfoResponse, err error) {
    userInfo = GenericUserInfoResponse{}

	res, err := client.Get(url)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to get userinfo from generic provider")
		return userInfo, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		errMsg := "Generic provider userinfo endpoint returned non-OK status"
		log.Error().Int("status", res.StatusCode).Str("url", url).Msg(errMsg)
		return userInfo, errors.New(errMsg)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to read userinfo response body")
		return userInfo, err
	}
	log.Debug().Bytes("body", body).Msg("Read userinfo body from generic provider")

	// Unmarshal into the userInfo struct
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to parse userinfo JSON")
		return userInfo, err
	}

	// Log parsed info
	log.Debug().
		Str("email", userInfo.Email).
		Strs("groups", userInfo.Groups).
		Str("name", userInfo.Name).
		Str("preferred_username", userInfo.PreferredUsername).
		Str("sub", userInfo.Sub).
		Msg("Parsed userinfo from generic provider")

	// Check if essential identifier (e.g., email or sub) is present
	if userInfo.Email == "" && userInfo.Sub == "" {
	    log.Error().Msg("Userinfo response missing essential identifier (email or sub)")
	    return userInfo, errors.New("userinfo missing identifier")
	}

	return userInfo, nil
}