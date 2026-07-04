package forwardauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

type testAppConfigProvider struct {
	cfg *model.AppConfig
}

func (p testAppConfigProvider) GetDbConfig() *model.AppConfig {
	return p.cfg
}

func TestService_validateReturnToRejectsPathTraversalOutsidePrefix(t *testing.T) {
	service, client, _ := newTestService(t)

	validReturnTo, err := service.validateReturnTo(client, "https://app.example.com/app/dashboard")
	require.NoError(t, err)
	require.Equal(t, "https://app.example.com/app/dashboard", validReturnTo)

	_, err = service.validateReturnTo(client, "https://app.example.com/app/../admin")
	require.ErrorContains(t, err, "outside of the protected application")
}

func TestService_validateProxySession(t *testing.T) {
	service, client, user := newTestService(t)

	rawToken, duration, err := service.createProxySession(t.Context(), client.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, time.Hour, duration)

	validatedUser, err := service.validateProxySession(t.Context(), client, rawToken)
	require.NoError(t, err)
	require.Equal(t, user.ID, validatedUser.ID)
	require.Equal(t, user.Username, validatedUser.Username)

	require.NoError(t, service.db.Model(&model.User{}).Where("id = ?", user.ID).Update("disabled", true).Error)

	_, err = service.validateProxySession(t.Context(), client, rawToken)
	require.ErrorIs(t, err, errForwardAuthAccessDenied)
}

func TestService_loginAndCallbackURLs(t *testing.T) {
	service, client, _ := newTestService(t)

	assert.Equal(
		t,
		"https://pocket-id.example.com/login?redirect=%2Fapi%2Fforward-auth%2Fcomplete%2Fclient-1%3Ftoken%3Dlogin-token",
		service.loginRedirectURL(client.ID, "login-token"),
	)

	startURL, err := service.startURL(client, "https://app.example.com/app/dashboard")
	require.NoError(t, err)
	assert.Equal(
		t,
		"https://app.example.com/.pocket-id/start/client-1?return_to=https%3A%2F%2Fapp.example.com%2Fapp%2Fdashboard",
		startURL,
	)

	callbackURL, err := service.callbackURL(client, "login-token")
	require.NoError(t, err)
	assert.Equal(
		t,
		"https://app.example.com/.pocket-id/callback/client-1?token=login-token",
		callbackURL,
	)
}

func newTestService(t *testing.T) (*Service, model.OidcClient, model.User) {
	t.Helper()

	db := testutils.NewDatabaseForTest(t)
	cfg := &model.AppConfig{
		SessionDuration: model.AppConfigVariable{Value: "60"},
	}
	service := newService(Dependencies{
		DB:        db,
		AppConfig: testAppConfigProvider{cfg: cfg},
		BaseURL:   "https://pocket-id.example.com",
	})

	group := model.UserGroup{
		Base:         model.Base{ID: "group-1"},
		Name:         "admins",
		FriendlyName: "Admins",
	}
	require.NoError(t, db.Create(&group).Error)

	user := model.User{
		Base:        model.Base{ID: "user-1"},
		Username:    "alice",
		Email:       stringPtr("alice@example.com"),
		FirstName:   "Alice",
		LastName:    "Example",
		DisplayName: "Alice Example",
		IsAdmin:     true,
	}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Model(&user).Association("UserGroups").Append(&group))

	externalURL := "https://app.example.com/app"
	upstreamURL := "http://upstream.example.internal/base"
	client := model.OidcClient{
		Base:                   model.Base{ID: "client-1"},
		Name:                   "Protected App",
		CallbackURLs:           model.UrlList{"https://pocket-id.example.com/callback"},
		IsGroupRestricted:      true,
		ForwardAuthEnabled:     true,
		ForwardAuthExternalURL: &externalURL,
		ForwardAuthUpstreamURL: &upstreamURL,
	}
	require.NoError(t, db.Create(&client).Error)
	require.NoError(t, db.Model(&client).Association("AllowedUserGroups").Append(&group))

	client, err := service.getClient(t.Context(), client.ID)
	require.NoError(t, err)

	return service, client, user
}

func TestCleanupExpiredSessionsAndLoginTokens(t *testing.T) {
	db := testutils.NewDatabaseForTest(t)

	user := model.User{
		Base:      model.Base{ID: "user-1"},
		Username:  "alice",
		FirstName: "Alice",
	}
	require.NoError(t, db.Create(&user).Error)

	externalURL := "https://app.example.com/app"
	client := model.OidcClient{
		Base:                   model.Base{ID: "client-1"},
		Name:                   "Protected App",
		CallbackURLs:           model.UrlList{"https://pocket-id.example.com/callback"},
		ForwardAuthEnabled:     true,
		ForwardAuthExternalURL: &externalURL,
	}
	require.NoError(t, db.Create(&client).Error)

	now := time.Now()
	expired := datatype.DateTime(now.Add(-time.Hour))
	future := datatype.DateTime(now.Add(time.Hour))

	rows := []Session{
		{Base: model.Base{ID: "expired-session"}, Token: "expired-session", ExpiresAt: expired, UserID: user.ID, ClientID: client.ID},
		{Base: model.Base{ID: "active-session"}, Token: "active-session", ExpiresAt: future, UserID: user.ID, ClientID: client.ID},
	}
	for i := range rows {
		require.NoError(t, db.Create(&rows[i]).Error)
	}

	loginTokens := []LoginToken{
		{Base: model.Base{ID: "expired-login"}, Token: "expired-login", ReturnTo: externalURL, ExpiresAt: expired, ClientID: client.ID},
		{Base: model.Base{ID: "active-login"}, Token: "active-login", ReturnTo: externalURL, ExpiresAt: future, ClientID: client.ID},
	}
	for i := range loginTokens {
		require.NoError(t, db.Create(&loginTokens[i]).Error)
	}

	deletedSessions, err := CleanupExpiredSessions(t.Context(), db)
	require.NoError(t, err)
	require.Equal(t, int64(1), deletedSessions)

	deletedLoginTokens, err := CleanupExpiredLoginTokens(t.Context(), db)
	require.NoError(t, err)
	require.Equal(t, int64(1), deletedLoginTokens)

	var sessionIDs []string
	require.NoError(t, db.Model(&Session{}).Order("id").Pluck("id", &sessionIDs).Error)
	require.Equal(t, []string{"active-session"}, sessionIDs)

	var loginTokenIDs []string
	require.NoError(t, db.Model(&LoginToken{}).Order("id").Pluck("id", &loginTokenIDs).Error)
	require.Equal(t, []string{"active-login"}, loginTokenIDs)
}

func stringPtr(value string) *string {
	return &value
}
