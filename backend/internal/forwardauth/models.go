package forwardauth

import (
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
)

type Session struct {
	model.Base

	Token     string            `gorm:"uniqueIndex"`
	ExpiresAt datatype.DateTime `gorm:"index"`

	UserID string
	User   model.User

	ClientID string
	Client   model.OidcClient
}

func (Session) TableName() string {
	return "forward_auth_sessions"
}

type LoginToken struct {
	model.Base

	Token     string `gorm:"uniqueIndex"`
	ReturnTo  string
	ExpiresAt datatype.DateTime `gorm:"index"`

	UserID *string
	User   *model.User

	ClientID string
	Client   model.OidcClient
}

func (LoginToken) TableName() string {
	return "forward_auth_login_tokens"
}
