// Copyright © 2018 Camunda Services GmbH (info@camunda.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zbc

import (
	"context"
	"fmt"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net/url"
	"strconv"
	"time"
)

const OAuthClientIdEnvVar = "ZEEBE_CLIENT_ID"

// #nosec 101
const OAuthClientSecretEnvVar = "ZEEBE_CLIENT_SECRET"

// #nosec 101
const OAuthTokenAudienceEnvVar = "ZEEBE_TOKEN_AUDIENCE"
const OAuthAuthorizationUrlEnvVar = "ZEEBE_AUTHORIZATION_SERVER_URL"
const OAuthRequestTimeoutEnvVar = "ZEEBE_AUTH_REQUEST_TIMEOUT"

// OAuthDefaultAuthzURL points to the expected default URL for this credentials provider, the Camunda Cloud endpoint.
const OAuthDefaultAuthzURL = "https://login.cloud.camunda.io/oauth/token/"

// OAuthDefaultRequestTimeout is the default timeout for OAuth requests
const OAuthDefaultRequestTimeout = 10 * time.Second

// OAuthCredentialsProvider is a built-in CredentialsProvider that contains credentials obtained from an OAuth
// authorization server, including a token prefix and an access token. Using these values it sets the 'Authorization'
// header of each gRPC call.
type OAuthCredentialsProvider struct {
	timeout     time.Duration
	tokenSource *cachedTokenSource
}

// OAuthProviderConfig configures an OAuthCredentialsProvider, containing the required data to request an access token
// from an OAuth authorization server which will be appended to each gRPC call's headers.
type OAuthProviderConfig struct {
	// The client identifier used to request an access token. Can be overridden with the environment variable 'ZEEBE_CLIENT_ID'.
	ClientID string
	// The client secret used to request an access token. Can be overridden with the environment variable 'ZEEBE_CLIENT_SECRET'.
	ClientSecret string
	// The audience to which the access token will be sent. Can be overridden with the environment variable 'ZEEBE_TOKEN_AUDIENCE'.
	Audience string
	// The URL for the authorization server from which the access token will be requested. Can be overridden with
	// the environment variable 'ZEEBE_AUTHORIZATION_SERVER_URL'.
	AuthorizationServerURL string
	// Cache to read/write credentials from; if none given, defaults to an oauthYamlCredentialsCache instance with the
	// path '$HOME/.camunda/credentials' as default (can be overridden by 'ZEEBE_CLIENT_CONFIG_PATH')
	Cache OAuthCredentialsCache
	// Timeout is the maximum duration of an OAuth request. The default value is 10 seconds
	Timeout time.Duration
}

// ApplyCredentials takes a map of headers as input and adds an access token prefixed by a token type to the 'Authorization'
// header of a gRPC call.
func (p *OAuthCredentialsProvider) ApplyCredentials(ctx context.Context, headers map[string]string) error {
	token, err := p.tokenSource.Token(ctx)
	if err != nil {
		return status.Errorf(codes.Canceled, err.Error())
	}

	headers["Authorization"] = fmt.Sprintf("%s %s", token.Type(), token.AccessToken)
	return nil
}

// ShouldRetryRequest checks if the error is UNAUTHENTICATED and, if so, attempts to refresh the access token. If the
// new credentials are different from the stored ones, returns true. If the credentials are the same, returns false.
func (p *OAuthCredentialsProvider) ShouldRetryRequest(ctx context.Context, err error) bool {
	if status.Code(err) == codes.Unauthenticated {
		_, err := p.tokenSource.Token(ctx)
		if err != nil {
			log.Printf("Expected to refresh token after UNAUTHENTICATED response but: %s", err.Error())
			return false
		}

		return true
	}

	return false
}

// NewOAuthCredentialsProvider requests credentials from an authorization server and uses them to create an OAuthCredentialsProvider.
func NewOAuthCredentialsProvider(config *OAuthProviderConfig) (*OAuthCredentialsProvider, error) {
	if err := applyCredentialEnvOverrides(config); err != nil {
		return nil, err
	}
	applyCredentialDefaults(config)

	if err := validation.Validate(config.AuthorizationServerURL, is.URL); err != nil {
		return nil, fmt.Errorf("expected to find valid authz server URL '%s': %w", config.AuthorizationServerURL, err)
	} else if err := validation.Validate(config.ClientID, validation.Required); err != nil {
		return nil, fmt.Errorf("expected to find non-empty client id")
	} else if err := validation.Validate(config.ClientSecret, validation.Required); err != nil {
		return nil, fmt.Errorf("expected to find non-empty client secret")
	} else if err := validation.Validate(config.Audience, validation.Required); err != nil {
		return nil, fmt.Errorf("expected to find non-empty audience")
	}

	provider := OAuthCredentialsProvider{
		tokenSource: &cachedTokenSource{
			cache: config.Cache,
			cfg: &clientcredentials.Config{
				ClientID:     config.ClientID,
				ClientSecret: config.ClientSecret,
				Scopes:       []string{config.Audience},
				TokenURL:     config.AuthorizationServerURL,
			},
		},
		timeout: config.Timeout,
	}

	return &provider, nil
}

type cachedTokenSource struct {
	cache OAuthCredentialsCache
	cfg   *clientcredentials.Config
}

func (ts *cachedTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	audience := ts.cfg.Scopes[0]
	token := ts.cache.Get(audience)
	if token != nil && token.Valid() {
		return token, nil
	}

	token, err := ts.cfg.Token(ctx)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Token %s\n", token)

	err = ts.cache.Update(audience, token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func applyCredentialEnvOverrides(config *OAuthProviderConfig) error {
	if envClientID := env.get(OAuthClientIdEnvVar); envClientID != "" {
		config.ClientID = envClientID
	}
	if envClientSecret := env.get(OAuthClientSecretEnvVar); envClientSecret != "" {
		config.ClientSecret = envClientSecret
	}
	if envAudience := env.get(OAuthTokenAudienceEnvVar); envAudience != "" {
		config.Audience = envAudience
	}
	if envAuthzServerURL := env.get(OAuthAuthorizationUrlEnvVar); envAuthzServerURL != "" {
		config.AuthorizationServerURL = envAuthzServerURL
	}
	if envOAuthReqTimeout := env.get(OAuthRequestTimeoutEnvVar); envOAuthReqTimeout != "" {
		timeout, err := strconv.ParseUint(envOAuthReqTimeout, 10, 64)
		if err != nil {
			return fmt.Errorf("could not parse value of %s, should be non-negative amount: %w", OAuthRequestTimeoutEnvVar, err)
		}
		config.Timeout = time.Duration(timeout) * time.Millisecond
	}

	return nil
}

func applyCredentialDefaults(config *OAuthProviderConfig) {
	if config.AuthorizationServerURL == "" {
		config.AuthorizationServerURL = OAuthDefaultAuthzURL
	}

	if config.Cache == nil {
		cache, err := NewOAuthYamlCredentialsCache("")
		if err != nil {
			log.Printf("Failed to create OAuth YAML credentials cache with default path: %s", err.Error())
		} else {
			config.Cache = cache
		}
	}

	if config.Timeout <= time.Duration(0) {
		config.Timeout = OAuthDefaultRequestTimeout
	}
}
