package forwardauth

import (
	"github.com/gin-gonic/gin"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	"gorm.io/gorm"
)

type AppConfigProvider interface {
	GetDbConfig() *model.AppConfig
}

type Dependencies struct {
	DB        *gorm.DB
	AppConfig AppConfigProvider
	BaseURL   string
}

type Module struct {
	service *Service
	handler *handler
}

func New(deps Dependencies) *Module {
	service := newService(deps)

	return &Module{
		service: service,
		handler: newHandler(service),
	}
}

func (m *Module) RegisterRoutes(rootGroup *gin.RouterGroup, apiGroup *gin.RouterGroup, browserAuth gin.HandlerFunc) {
	rootGroup.GET("/.pocket-id/auth/:clientId", m.handler.authorize)
	rootGroup.GET("/.pocket-id/start/:clientId", m.handler.start)
	rootGroup.GET("/.pocket-id/callback/:clientId", m.handler.callback)
	rootGroup.GET("/.pocket-id/logout/:clientId", m.handler.logout)

	apiGroup.GET("/forward-auth/complete/:clientId", browserAuth, m.handler.complete)
}

func (m *Module) ProxyMiddleware() gin.HandlerFunc {
	return m.handler.proxyMiddleware()
}
