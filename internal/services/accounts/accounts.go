package accounts

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
	"github.com/spf13/viper"
)

type Accounts struct {
	baseUrl    string
	httpClient *http.Client
}

func New(baseUrl string, httpClient *http.Client) *Accounts {
	return &Accounts{
		baseUrl,
		httpClient,
	}
}

func NewWithConfig(config *viper.Viper) (*Accounts, error) {
	config.SetDefault("accounts.url", "https://account.ely.by")
	accountsUrl := strings.Trim(config.GetString("accounts.url"), "/")

	return New(accountsUrl, &http.Client{}), nil
}

type publicKeysResponse struct {
	Keys []struct {
		Alg string `json:"alg"`
		Pem string `json:"pem"`
	} `json:"keys"`
}

func (a *Accounts) GetPublicKeys(ctx context.Context) ([]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/public-keys", a.baseUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to form a correct request to Accounts: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform a request to Accounts: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received unexpected response code from accounts: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response from Accounts: %w", err)
	}

	var keys publicKeysResponse
	err = json.UnmarshalContext(ctx, body, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to parse json response: %w", err)
	}

	result := make([]crypto.PublicKey, len(keys.Keys))
	for i, key := range keys.Keys {
		block, _ := pem.Decode([]byte(key.Pem))
		if block == nil {
			return nil, fmt.Errorf("unable to decode pem block")
		}

		result[i], err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse a public key: %w", err)
		}
	}

	return result, nil
}
