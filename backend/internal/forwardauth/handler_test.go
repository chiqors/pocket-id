package forwardauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/model"
)

func TestForwardAuthFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, client, user := newTestService(t)
	router := newTestRouter(service, user.ID)

	returnTo := "https://app.example.com/app/dashboard"

	startRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/start/" + client.ID + "?return_to=" + url.QueryEscape(returnTo),
		host:   "app.example.com",
		proto:  "https",
	})
	require.Equal(t, http.StatusFound, startRecorder.Code)
	require.Equal(t, "no-store", startRecorder.Header().Get("Cache-Control"))

	loginLocation := parseURL(t, startRecorder.Header().Get("Location"))
	require.Equal(t, "https://pocket-id.example.com/login", loginLocation.Scheme+"://"+loginLocation.Host+loginLocation.Path)

	completePath := loginLocation.Query().Get("redirect")
	require.NotEmpty(t, completePath)

	completeRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: completePath,
		host:   "pocket-id.example.com",
		proto:  "https",
	})
	require.Equal(t, http.StatusFound, completeRecorder.Code)

	callbackLocation := parseURL(t, completeRecorder.Header().Get("Location"))
	require.Equal(t, "https://app.example.com/.pocket-id/callback/"+client.ID, callbackLocation.Scheme+"://"+callbackLocation.Host+callbackLocation.Path)

	callbackRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: callbackLocation.RequestURI(),
		host:   "app.example.com",
		proto:  "https",
	})
	require.Equal(t, http.StatusFound, callbackRecorder.Code)
	require.Equal(t, returnTo, callbackRecorder.Header().Get("Location"))

	sessionCookie := findCookie(t, callbackRecorder.Result().Cookies(), "__Host-pid-fa-")
	require.NotEmpty(t, sessionCookie.Value)
	assert.True(t, sessionCookie.HttpOnly)
	assert.True(t, sessionCookie.Secure)
	assert.Equal(t, "/", sessionCookie.Path)

	authorizeRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/auth/" + client.ID,
		host:   "app.example.com",
		proto:  "https",
		cookie: sessionCookie,
		headers: map[string]string{
			"X-Forwarded-Uri": "/app/dashboard",
		},
	})
	require.Equal(t, http.StatusNoContent, authorizeRecorder.Code)
	assert.Equal(t, user.ID, authorizeRecorder.Header().Get("X-Pocket-Id-User-Id"))
	assert.Equal(t, user.Username, authorizeRecorder.Header().Get("X-Pocket-Id-Username"))
	assert.Equal(t, user.FullName(), authorizeRecorder.Header().Get("X-Pocket-Id-Name"))
	assert.Equal(t, user.DisplayName, authorizeRecorder.Header().Get("X-Pocket-Id-Display-Name"))
	assert.Equal(t, "true", authorizeRecorder.Header().Get("X-Pocket-Id-Is-Admin"))
	assert.Equal(t, client.ID, authorizeRecorder.Header().Get("X-Pocket-Id-Client-Id"))
	assert.Equal(t, "admins", authorizeRecorder.Header().Get("X-Pocket-Id-Groups"))
	assert.Equal(t, "alice@example.com", authorizeRecorder.Header().Get("X-Pocket-Id-Email"))

	logoutRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/logout/" + client.ID + "?return_to=" + url.QueryEscape(returnTo),
		host:   "app.example.com",
		proto:  "https",
		cookie: sessionCookie,
	})
	require.Equal(t, http.StatusFound, logoutRecorder.Code)
	require.Equal(t, returnTo, logoutRecorder.Header().Get("Location"))

	clearedCookie := findCookie(t, logoutRecorder.Result().Cookies(), sessionCookie.Name)
	assert.Empty(t, clearedCookie.Value)
	assert.Equal(t, -1, clearedCookie.MaxAge)

	postLogoutRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/auth/" + client.ID,
		host:   "app.example.com",
		proto:  "https",
		cookie: sessionCookie,
		headers: map[string]string{
			"X-Forwarded-Uri": "/app/dashboard",
		},
	})
	require.Equal(t, http.StatusFound, postLogoutRecorder.Code)
	assert.True(t, strings.HasPrefix(postLogoutRecorder.Header().Get("Location"), "https://app.example.com/.pocket-id/start/"+client.ID))
}

func TestAuthorizeClearsCookieWhenUserNoLongerHasAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, client, user := newTestService(t)
	router := newTestRouter(service, user.ID)

	rawToken, _, err := service.createProxySession(t.Context(), client.ID, user.ID)
	require.NoError(t, err)
	require.NoError(t, service.db.Model(&model.User{}).Where("id = ?", user.ID).Update("disabled", true).Error)

	cookieName, _, err := sessionCookieSpec(client)
	require.NoError(t, err)

	authorizeRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/auth/" + client.ID,
		host:   "app.example.com",
		proto:  "https",
		cookie: &http.Cookie{
			Name:  cookieName,
			Value: rawToken,
		},
		headers: map[string]string{
			"X-Forwarded-Uri": "/app/dashboard",
		},
	})
	require.Equal(t, http.StatusForbidden, authorizeRecorder.Code)

	clearedCookie := findCookie(t, authorizeRecorder.Result().Cookies(), cookieName)
	assert.Empty(t, clearedCookie.Value)
	assert.Equal(t, -1, clearedCookie.MaxAge)
}

func TestProxyProviderFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, client, user := newTestService(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, strings.Join([]string{
			r.URL.Path,
			r.URL.RawQuery,
			r.Header.Get("X-Pocket-Id-User-Id"),
			r.Header.Get("X-Pocket-Id-Username"),
			r.Header.Get("X-Pocket-Id-Email"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-Uri"),
		}, "\n"))
	}))
	defer upstream.Close()

	require.NoError(t, service.db.Model(&model.OidcClient{}).Where("id = ?", client.ID).
		Update("forward_auth_upstream_url", upstream.URL+"/base").Error)

	client, err := service.getClient(t.Context(), client.ID)
	require.NoError(t, err)

	router := newTestRouter(service, user.ID)

	startRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/app/dashboard?view=full",
		host:   "app.example.com",
		proto:  "https",
	})
	require.Equal(t, http.StatusFound, startRecorder.Code)
	require.Equal(t, "https://app.example.com/.pocket-id/start/"+client.ID+"?return_to=https%3A%2F%2Fapp.example.com%2Fapp%2Fdashboard%3Fview%3Dfull", startRecorder.Header().Get("Location"))

	loginToken, err := service.createLoginToken(t.Context(), client.ID, "https://app.example.com/app/dashboard?view=full")
	require.NoError(t, err)
	require.NoError(t, service.markLoginTokenAuthenticated(t.Context(), client.ID, loginToken, user.ID))

	callbackRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/.pocket-id/callback/" + client.ID + "?token=" + url.QueryEscape(loginToken),
		host:   "app.example.com",
		proto:  "https",
	})
	require.Equal(t, http.StatusFound, callbackRecorder.Code)
	sessionCookie := findCookie(t, callbackRecorder.Result().Cookies(), "__Host-pid-fa-")

	proxyRecorder := doForwardAuthRequest(t, router, requestSpec{
		method: http.MethodGet,
		target: "/app/dashboard?view=full",
		host:   "app.example.com",
		proto:  "https",
		cookie: sessionCookie,
	})
	require.Equal(t, http.StatusOK, proxyRecorder.Code)
	require.Equal(t, "/base/dashboard\nview=full\nuser-1\nalice\nalice@example.com\napp.example.com\nhttps\n/app/dashboard?view=full", strings.TrimSpace(proxyRecorder.Body.String()))
}

type requestSpec struct {
	method  string
	target  string
	host    string
	proto   string
	cookie  *http.Cookie
	headers map[string]string
}

func newTestRouter(service *Service, userID string) *gin.Engine {
	router := gin.New()
	module := &Module{
		service: service,
		handler: newHandler(service),
	}
	router.Use(module.ProxyMiddleware())

	rootGroup := router.Group("/")
	apiGroup := router.Group("/api")
	module.RegisterRoutes(rootGroup, apiGroup, func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	return router
}

func doForwardAuthRequest(t *testing.T, router *gin.Engine, spec requestSpec) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), spec.method, spec.target, nil)
	req.Host = spec.host
	req.Header.Set("X-Forwarded-Host", spec.host)
	req.Header.Set("X-Forwarded-Proto", spec.proto)
	if spec.cookie != nil {
		req.AddCookie(spec.cookie)
	}
	for key, value := range spec.headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	return recorder
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(raw)
	require.NoError(t, err)

	return parsedURL
}

func findCookie(t *testing.T, cookies []*http.Cookie, namePrefix string) *http.Cookie {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == namePrefix || strings.HasPrefix(cookie.Name, namePrefix) {
			return cookie
		}
	}

	t.Fatalf("cookie with prefix %q not found", namePrefix)
	return nil
}
