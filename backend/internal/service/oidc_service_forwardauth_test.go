package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/model"
)

func TestNormalizeForwardAuthExternalURL(t *testing.T) {
	tests := []struct {
		name      string
		input     *string
		want      *string
		wantError string
	}{
		{
			name:  "empty value is ignored",
			input: stringPtr(" "),
		},
		{
			name:  "absolute url is trimmed and normalized",
			input: stringPtr(" https://app.example.com/base/ "),
			want:  stringPtr("https://app.example.com/base"),
		},
		{
			name:      "relative url is rejected",
			input:     stringPtr("/app"),
			wantError: "forward auth external URL must be absolute",
		},
		{
			name:      "non http scheme is rejected",
			input:     stringPtr("ftp://app.example.com"),
			wantError: "forward auth external URL must use http or https",
		},
		{
			name:      "query string is rejected",
			input:     stringPtr("https://app.example.com/app?next=1"),
			wantError: "forward auth external URL cannot include a query string or fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeForwardAuthExternalURL(tt.input)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeForwardAuthUpstreamURL(t *testing.T) {
	tests := []struct {
		name      string
		input     *string
		want      *string
		wantError string
	}{
		{
			name:  "empty value is ignored",
			input: stringPtr(" "),
		},
		{
			name:  "absolute url is trimmed and normalized",
			input: stringPtr(" http://nginx.nginx.svc.cluster.local:80/ "),
			want:  stringPtr("http://nginx.nginx.svc.cluster.local:80"),
		},
		{
			name:      "relative url is rejected",
			input:     stringPtr("/nginx"),
			wantError: "forward auth upstream URL must be absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeForwardAuthUpstreamURL(tt.input)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUpdateOIDCClientModelFromDtoRequiresForwardAuthExternalURL(t *testing.T) {
	client := model.OidcClient{}

	err := updateOIDCClientModelFromDto(&client, &dto.OidcClientUpdateDto{
		Name:               "Protected App",
		ForwardAuthEnabled: true,
	})
	require.Error(t, err)

	var validationErr *common.ValidationError
	require.ErrorAs(t, err, &validationErr)
	require.Equal(t, "forward auth external URL is required when forward auth is enabled", validationErr.Message)
}

func TestUpdateOIDCClientModelFromDtoStoresForwardAuthFields(t *testing.T) {
	client := model.OidcClient{}

	err := updateOIDCClientModelFromDto(&client, &dto.OidcClientUpdateDto{
		Name:                             "Protected App",
		ForwardAuthEnabled:               true,
		ForwardAuthExternalURL:           stringPtr("https://app.example.com/protected/"),
		ForwardAuthUpstreamURL:           stringPtr("http://nginx.nginx.svc.cluster.local:80/"),
		ForwardAuthInjectIdentityHeaders: true,
		ForwardAuthUpstreamHeaders: []dto.HTTPHeaderDto{
			{Name: "X-API-Key", Value: "super-secret"},
			{Name: "Authorization", Value: "Bearer internal-token"},
		},
	})
	require.NoError(t, err)
	require.True(t, client.ForwardAuthEnabled)
	require.NotNil(t, client.ForwardAuthExternalURL)
	require.Equal(t, "https://app.example.com/protected", *client.ForwardAuthExternalURL)
	require.NotNil(t, client.ForwardAuthUpstreamURL)
	require.Equal(t, "http://nginx.nginx.svc.cluster.local:80", *client.ForwardAuthUpstreamURL)
	require.True(t, client.ForwardAuthInjectIdentityHeaders)
	require.Equal(t, model.HTTPHeaderList{
		{Name: "X-Api-Key", Value: "super-secret"},
		{Name: "Authorization", Value: "Bearer internal-token"},
	}, client.ForwardAuthUpstreamHeaders)
}

func TestUpdateOIDCClientModelFromDtoRejectsReservedForwardAuthHeaders(t *testing.T) {
	client := model.OidcClient{}

	err := updateOIDCClientModelFromDto(&client, &dto.OidcClientUpdateDto{
		Name:                   "Protected App",
		ForwardAuthEnabled:     true,
		ForwardAuthExternalURL: stringPtr("https://app.example.com/protected/"),
		ForwardAuthUpstreamHeaders: []dto.HTTPHeaderDto{
			{Name: "X-Forwarded-Host", Value: "spoofed.example.com"},
		},
	})
	require.ErrorContains(t, err, `forward auth upstream header "X-Forwarded-Host" is reserved`)
}

func stringPtr(value string) *string {
	return &value
}
