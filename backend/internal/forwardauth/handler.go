package forwardauth

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"gorm.io/gorm"
)

type handler struct {
	service *Service
}

func newHandler(service *Service) *handler {
	return &handler{service: service}
}

func (h *handler) authorize(c *gin.Context) {
	setNoStoreHeaders(c)

	client, err := h.service.getClient(c.Request.Context(), c.Param("clientId"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	protectedURL, err := forwardedProtectedURL(c.Request)
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	returnTo, err := h.service.validateReturnTo(client, protectedURL.String())
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	cookieName, secure, err := sessionCookieSpec(client)
	if err != nil {
		_ = c.Error(err)
		return
	}

	rawToken, _ := c.Cookie(cookieName)
	user, err := h.service.validateProxySession(c.Request.Context(), client, rawToken)
	switch {
	case err == nil:
		writeIdentityHeaders(c, user, client.ID)
		c.Status(http.StatusNoContent)
		return
	case errors.Is(err, errProxySessionNotFound):
		clearSessionCookie(c, cookieName, secure)
		startURL, err := h.service.startURL(client, returnTo)
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.Redirect(http.StatusFound, startURL)
		return
	case errors.Is(err, errForwardAuthAccessDenied):
		clearSessionCookie(c, cookieName, secure)
		c.Status(http.StatusForbidden)
		return
	default:
		_ = c.Error(err)
		return
	}
}

func (h *handler) start(c *gin.Context) {
	setNoStoreHeaders(c)

	client, err := h.service.getClient(c.Request.Context(), c.Param("clientId"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	currentURL, err := requestPublicURL(c.Request)
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}
	if err := h.service.validateBrowserRouteURL(client, currentURL.String()); err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	returnTo, err := h.service.validateReturnTo(client, c.Query("return_to"))
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	cookieName, secure, err := sessionCookieSpec(client)
	if err != nil {
		_ = c.Error(err)
		return
	}

	if rawToken, err := c.Cookie(cookieName); err == nil {
		if _, err := h.service.validateProxySession(c.Request.Context(), client, rawToken); err == nil {
			c.Redirect(http.StatusFound, returnTo)
			return
		}

		clearSessionCookie(c, cookieName, secure)
	}

	loginToken, err := h.service.createLoginToken(c.Request.Context(), client.ID, returnTo)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.Redirect(http.StatusFound, h.service.loginRedirectURL(client.ID, loginToken))
}

func (h *handler) complete(c *gin.Context) {
	setNoStoreHeaders(c)

	client, err := h.service.getClient(c.Request.Context(), c.Param("clientId"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	loginToken := strings.TrimSpace(c.Query("token"))
	if loginToken == "" {
		_ = c.Error(&common.ValidationError{Message: "token is required"})
		return
	}

	userID := c.GetString("userID")
	if userID == "" {
		_ = c.Error(&common.NotSignedInError{})
		return
	}

	if _, err := h.service.validateUserAccess(c.Request.Context(), userID, client); err != nil {
		if errors.Is(err, errForwardAuthAccessDenied) {
			_ = c.Error(&common.OidcAccessDeniedError{})
			return
		}

		_ = c.Error(err)
		return
	}

	if err := h.service.markLoginTokenAuthenticated(c.Request.Context(), client.ID, loginToken, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = c.Error(&common.TokenInvalidOrExpiredError{})
			return
		}

		_ = c.Error(err)
		return
	}

	callbackURL, err := h.service.callbackURL(client, loginToken)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.Redirect(http.StatusFound, callbackURL)
}

func (h *handler) callback(c *gin.Context) {
	setNoStoreHeaders(c)

	client, err := h.service.getClient(c.Request.Context(), c.Param("clientId"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	currentURL, err := requestPublicURL(c.Request)
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}
	if err := h.service.validateBrowserRouteURL(client, currentURL.String()); err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	loginToken := strings.TrimSpace(c.Query("token"))
	if loginToken == "" {
		_ = c.Error(&common.ValidationError{Message: "token is required"})
		return
	}

	token, err := h.service.consumeLoginToken(c.Request.Context(), client.ID, loginToken)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		_ = c.Error(&common.TokenInvalidOrExpiredError{})
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	if token.UserID == nil || *token.UserID == "" {
		_ = c.Error(&common.TokenInvalidOrExpiredError{})
		return
	}

	if _, err := h.service.validateUserAccess(c.Request.Context(), *token.UserID, client); err != nil {
		if errors.Is(err, errForwardAuthAccessDenied) {
			_ = c.Error(&common.OidcAccessDeniedError{})
			return
		}

		_ = c.Error(err)
		return
	}

	sessionToken, sessionDuration, err := h.service.createProxySession(c.Request.Context(), client.ID, *token.UserID)
	if err != nil {
		_ = c.Error(err)
		return
	}

	cookieName, secure, err := sessionCookieSpec(client)
	if err != nil {
		_ = c.Error(err)
		return
	}

	setSessionCookie(c, cookieName, sessionToken, int(sessionDuration.Seconds()), secure)
	c.Redirect(http.StatusFound, token.ReturnTo)
}

func (h *handler) logout(c *gin.Context) {
	setNoStoreHeaders(c)

	client, err := h.service.getClient(c.Request.Context(), c.Param("clientId"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	currentURL, err := requestPublicURL(c.Request)
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}
	if err := h.service.validateBrowserRouteURL(client, currentURL.String()); err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	returnTo, err := h.service.validateReturnTo(client, c.Query("return_to"))
	if err != nil {
		_ = c.Error(&common.ValidationError{Message: err.Error()})
		return
	}

	cookieName, secure, err := sessionCookieSpec(client)
	if err != nil {
		_ = c.Error(err)
		return
	}

	if rawToken, err := c.Cookie(cookieName); err == nil {
		if err := h.service.deleteProxySession(c.Request.Context(), client.ID, rawToken); err != nil {
			_ = c.Error(err)
			return
		}
	}

	clearSessionCookie(c, cookieName, secure)
	c.Redirect(http.StatusFound, returnTo)
}

func setNoStoreHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
}

func setSessionCookie(c *gin.Context, name, value string, maxAgeSeconds int, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		Expires:  time.Now().Add(time.Duration(maxAgeSeconds) * time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(c *gin.Context, name string, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func sessionCookieSpec(client model.OidcClient) (string, bool, error) {
	externalURL, err := parseExternalURL(client)
	if err != nil {
		return "", false, err
	}

	suffix := utils.CreateSha256Hash(client.ID)[:12]
	if strings.EqualFold(externalURL.Scheme, "https") {
		return "__Host-pid-fa-" + suffix, true, nil
	}

	return "pid-fa-" + suffix, false, nil
}

func writeIdentityHeaders(c *gin.Context, user model.User, clientID string) {
	groups := make([]string, len(user.UserGroups))
	for i, group := range user.UserGroups {
		groups[i] = group.Name
	}
	slices.Sort(groups)

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.FullName()
	}

	c.Header("X-Pocket-Id-User-Id", user.ID)
	c.Header("X-Pocket-Id-Username", user.Username)
	c.Header("X-Pocket-Id-Name", user.FullName())
	c.Header("X-Pocket-Id-Display-Name", displayName)
	c.Header("X-Pocket-Id-Is-Admin", strconv.FormatBool(user.IsAdmin))
	c.Header("X-Pocket-Id-Client-Id", clientID)
	c.Header("X-Pocket-Id-Groups", strings.Join(groups, ","))
	if user.Email != nil && *user.Email != "" {
		c.Header("X-Pocket-Id-Email", *user.Email)
	}
}

func requestPublicURL(r *http.Request) (*url.URL, error) {
	scheme := forwardedHeaderValue(r, "X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := forwardedHeaderValue(r, "X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return nil, errors.New("request host is required")
	}

	uri := forwardedHeaderValue(r, "X-Forwarded-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	if uri == "" {
		uri = "/"
	}

	return url.Parse(scheme + "://" + host + uri)
}

func forwardedProtectedURL(r *http.Request) (*url.URL, error) {
	uri := forwardedHeaderValue(r, "X-Forwarded-Uri")
	if uri == "" {
		uri = forwardedHeaderValue(r, "X-Original-Uri")
	}
	if uri == "" {
		return nil, errors.New("X-Forwarded-Uri header is required")
	}

	scheme := forwardedHeaderValue(r, "X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := forwardedHeaderValue(r, "X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return nil, errors.New("request host is required")
	}

	return url.Parse(scheme + "://" + host + uri)
}

func forwardedHeaderValue(r *http.Request, key string) string {
	value := strings.TrimSpace(r.Header.Get(key))
	if value == "" {
		return ""
	}

	firstValue, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(firstValue)
}
