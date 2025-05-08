package metabase

import (
	"context"
	"errors"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
)

// Authenticates to the Metabase API using the given username and password, and returns an API client configured with
// the session obtained during authentication.
func MakeAuthenticatedClientWithUsernameAndPassword(ctx context.Context, endpoint string, username string, password string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClientWithResponses(endpoint)
	if err != nil {
		return nil, err
	}

	sessionResp, err := client.CreateSessionWithResponse(ctx, CreateSessionBody{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	if sessionResp.StatusCode() != 200 || sessionResp.JSON200 == nil {
		return nil, errors.New("received unexpected response from the Metabase session API")
	}

	// Authenticated calls are made by passing the session ID in a Metabase-specific header.
	apiKeyProvider, err := securityprovider.NewSecurityProviderApiKey("header", "X-Metabase-Session", sessionResp.JSON200.Id)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithRequestEditorFn(apiKeyProvider.Intercept))
	authenticatedClient, err := NewClientWithResponses(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	return authenticatedClient, nil
}

// Returns an API client configured with the given API key.
func MakeAuthenticatedClientWithApiKey(ctx context.Context, endpoint string, apiKey string, opts ...ClientOption) (*ClientWithResponses, error) {
	apiKeyProvider, err := securityprovider.NewSecurityProviderApiKey("header", "X-Api-Key", apiKey)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithRequestEditorFn(apiKeyProvider.Intercept))
	authenticatedClient, err := NewClientWithResponses(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	return authenticatedClient, nil
}
