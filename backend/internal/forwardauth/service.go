package forwardauth

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/oidc"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const loginTokenLifetime = 15 * time.Minute

var (
	errForwardAuthAccessDenied = errors.New("forward auth access denied")
	errProxySessionNotFound    = errors.New("forward auth proxy session not found")
)

type Service struct {
	db        *gorm.DB
	appConfig AppConfigProvider
	baseURL   string
}

func newService(deps Dependencies) *Service {
	return &Service{
		db:        deps.DB,
		appConfig: deps.AppConfig,
		baseURL:   strings.TrimRight(deps.BaseURL, "/"),
	}
}

func (s *Service) getClient(ctx context.Context, clientID string) (model.OidcClient, error) {
	var client model.OidcClient
	err := s.db.
		WithContext(ctx).
		Preload("AllowedUserGroups").
		First(&client, "id = ?", clientID).
		Error
	if err != nil {
		return model.OidcClient{}, err
	}

	if !client.ForwardAuthEnabled || client.ForwardAuthExternalURL == nil || *client.ForwardAuthExternalURL == "" {
		return model.OidcClient{}, gorm.ErrRecordNotFound
	}

	return client, nil
}

func (s *Service) validateUserAccess(ctx context.Context, userID string, client model.OidcClient) (model.User, error) {
	var user model.User
	err := s.db.
		WithContext(ctx).
		Preload("UserGroups").
		First(&user, "id = ?", userID).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, errProxySessionNotFound
	}
	if err != nil {
		return model.User{}, err
	}

	if user.Disabled || !oidc.IsUserGroupAllowedToAuthorize(user, client) {
		return model.User{}, errForwardAuthAccessDenied
	}

	return user, nil
}

func (s *Service) validateProxySession(ctx context.Context, client model.OidcClient, rawToken string) (model.User, error) {
	if rawToken == "" {
		return model.User{}, errProxySessionNotFound
	}

	var session Session
	err := s.db.
		WithContext(ctx).
		First(&session, "token = ? AND client_id = ? AND expires_at > ?", hashToken(rawToken), client.ID, datatype.DateTime(time.Now())).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, errProxySessionNotFound
	}
	if err != nil {
		return model.User{}, err
	}

	return s.validateUserAccess(ctx, session.UserID, client)
}

func (s *Service) createLoginToken(ctx context.Context, clientID, returnTo string) (string, error) {
	rawToken, err := utils.GenerateRandomAlphanumericString(32)
	if err != nil {
		return "", err
	}

	loginToken := LoginToken{
		Token:     hashToken(rawToken),
		ReturnTo:  returnTo,
		ExpiresAt: datatype.DateTime(time.Now().Add(loginTokenLifetime)),
		ClientID:  clientID,
	}

	if err := s.db.WithContext(ctx).Create(&loginToken).Error; err != nil {
		return "", err
	}

	return rawToken, nil
}

func (s *Service) markLoginTokenAuthenticated(ctx context.Context, clientID, rawToken, userID string) error {
	now := datatype.DateTime(time.Now())

	st := s.db.
		WithContext(ctx).
		Model(&LoginToken{}).
		Where("token = ? AND client_id = ? AND expires_at > ?", hashToken(rawToken), clientID, now).
		Update("user_id", userID)
	if st.Error != nil {
		return st.Error
	}
	if st.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (s *Service) consumeLoginToken(ctx context.Context, clientID, rawToken string) (LoginToken, error) {
	var loginToken LoginToken
	st := s.db.
		WithContext(ctx).
		Clauses(clause.Returning{}).
		Delete(&loginToken, "token = ? AND client_id = ? AND expires_at > ?", hashToken(rawToken), clientID, datatype.DateTime(time.Now()))
	if st.Error != nil {
		return LoginToken{}, st.Error
	}
	if st.RowsAffected == 0 {
		return LoginToken{}, gorm.ErrRecordNotFound
	}

	return loginToken, nil
}

func (s *Service) createProxySession(ctx context.Context, clientID, userID string) (string, time.Duration, error) {
	rawToken, err := utils.GenerateRandomAlphanumericString(32)
	if err != nil {
		return "", 0, err
	}

	sessionDuration := s.appConfig.GetDbConfig().SessionDuration.AsDurationMinutes()
	session := Session{
		Token:     hashToken(rawToken),
		ExpiresAt: datatype.DateTime(time.Now().Add(sessionDuration)),
		UserID:    userID,
		ClientID:  clientID,
	}

	if err := s.db.WithContext(ctx).Create(&session).Error; err != nil {
		return "", 0, err
	}

	return rawToken, sessionDuration, nil
}

func (s *Service) deleteProxySession(ctx context.Context, clientID, rawToken string) error {
	if rawToken == "" {
		return nil
	}

	return s.db.
		WithContext(ctx).
		Delete(&Session{}, "token = ? AND client_id = ?", hashToken(rawToken), clientID).
		Error
}

func (s *Service) loginRedirectURL(clientID, loginToken string) string {
	target := url.URL{
		Path: path.Join("/api/forward-auth/complete", url.PathEscape(clientID)),
	}

	query := target.Query()
	query.Set("token", loginToken)
	target.RawQuery = query.Encode()

	return s.baseURL + "/login?redirect=" + url.QueryEscape(target.RequestURI())
}

func (s *Service) startURL(client model.OidcClient, returnTo string) (string, error) {
	appURL, err := parseExternalURL(client)
	if err != nil {
		return "", err
	}

	startURL := url.URL{
		Scheme: appURL.Scheme,
		Host:   appURL.Host,
		Path:   path.Join("/", ".pocket-id", "start", client.ID),
	}

	query := startURL.Query()
	query.Set("return_to", returnTo)
	startURL.RawQuery = query.Encode()

	return startURL.String(), nil
}

func (s *Service) callbackURL(client model.OidcClient, loginToken string) (string, error) {
	appURL, err := parseExternalURL(client)
	if err != nil {
		return "", err
	}

	callbackURL := url.URL{
		Scheme: appURL.Scheme,
		Host:   appURL.Host,
		Path:   path.Join("/", ".pocket-id", "callback", client.ID),
	}

	query := callbackURL.Query()
	query.Set("token", loginToken)
	callbackURL.RawQuery = query.Encode()

	return callbackURL.String(), nil
}

func (s *Service) validateBrowserRouteURL(client model.OidcClient, raw string) error {
	externalURL, err := parseExternalURL(client)
	if err != nil {
		return err
	}

	actualURL, err := url.Parse(raw)
	if err != nil {
		return err
	}

	if !sameAuthority(externalURL, actualURL) {
		return errors.New("request host does not match the protected application host")
	}

	return nil
}

func (s *Service) validateReturnTo(client model.OidcClient, raw string) (string, error) {
	externalURL, err := parseExternalURL(client)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(raw) == "" {
		return externalURL.String(), nil
	}

	returnTo, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if returnTo.Scheme == "" || returnTo.Host == "" {
		return "", errors.New("return URL must be absolute")
	}

	if !sameAuthority(externalURL, returnTo) {
		return "", errors.New("return URL host does not match the protected application")
	}

	if !pathMatchesPrefix(externalURL.Path, returnTo.Path) {
		return "", errors.New("return URL path is outside of the protected application")
	}

	return returnTo.String(), nil
}

func hashToken(rawToken string) string {
	return utils.CreateSha256Hash(rawToken)
}

func parseExternalURL(client model.OidcClient) (*url.URL, error) {
	if client.ForwardAuthExternalURL == nil || *client.ForwardAuthExternalURL == "" {
		return nil, errors.New("forward auth external URL is missing")
	}

	return url.Parse(*client.ForwardAuthExternalURL)
}

func sameAuthority(expected *url.URL, actual *url.URL) bool {
	return strings.EqualFold(normalizeAuthority(expected), normalizeAuthority(actual)) &&
		strings.EqualFold(expected.Scheme, actual.Scheme)
}

func normalizeAuthority(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()

	switch {
	case port != "":
		return host + ":" + port
	case strings.EqualFold(u.Scheme, "http"):
		return host + ":80"
	case strings.EqualFold(u.Scheme, "https"):
		return host + ":443"
	default:
		return host
	}
}

func pathMatchesPrefix(prefix string, candidate string) bool {
	prefix = cleanPath(prefix)
	candidate = cleanPath(candidate)

	if prefix == "" || prefix == "/" {
		return true
	}

	if candidate == prefix {
		return true
	}

	return strings.HasPrefix(candidate, strings.TrimRight(prefix, "/")+"/")
}

func cleanPath(raw string) string {
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		return "/" + cleaned
	}

	return cleaned
}
