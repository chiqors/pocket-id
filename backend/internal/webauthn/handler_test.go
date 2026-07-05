package webauthn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type fakeForwardAuthSessionRevoker struct {
	userIDs []string
	err     error
}

func (f *fakeForwardAuthSessionRevoker) RevokeUserProxySessions(_ context.Context, userID string) error {
	f.userIDs = append(f.userIDs, userID)
	return f.err
}

func TestHandlerLogoutRevokesForwardAuthSessions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	revoker := &fakeForwardAuthSessionRevoker{}
	handler := newHandler(nil, nil, revoker)

	router := gin.New()
	router.POST("/api/webauthn/logout", func(c *gin.Context) {
		c.Set("userID", "user-1")
		handler.logout(c)
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/logout", nil)
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, []string{"user-1"}, revoker.userIDs)

	cookies := recorder.Result().Cookies()
	require.NotEmpty(t, cookies)
	require.Equal(t, "", cookies[0].Value)
}
