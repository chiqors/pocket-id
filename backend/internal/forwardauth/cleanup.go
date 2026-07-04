package forwardauth

import (
	"context"
	"time"

	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"gorm.io/gorm"
)

func CleanupExpiredSessions(ctx context.Context, db *gorm.DB) (int64, error) {
	st := db.
		WithContext(ctx).
		Delete(&Session{}, "expires_at < ?", datatype.DateTime(time.Now()))

	return st.RowsAffected, st.Error
}

func CleanupExpiredLoginTokens(ctx context.Context, db *gorm.DB) (int64, error) {
	st := db.
		WithContext(ctx).
		Delete(&LoginToken{}, "expires_at < ?", datatype.DateTime(time.Now()))

	return st.RowsAffected, st.Error
}
