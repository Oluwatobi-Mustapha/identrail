package api

import (
	"net/http"

	"github.com/Oluwatobi-Mustapha/aurelius/internal/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// NewRouter builds the REST surface area and observability endpoints.
func NewRouter(logger *zap.Logger, metrics *telemetry.Metrics) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.ScanRunsTotal, metrics.ScanDurationMS, metrics.FindingsGenerated)

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "aurelius",
		})
	})

	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))

	r.GET("/v1/findings", func(c *gin.Context) {
		logger.Info("findings requested")
		c.JSON(http.StatusOK, gin.H{
			"items": []string{},
		})
	})

	r.POST("/v1/scans", func(c *gin.Context) {
		metrics.ScanRunsTotal.Inc()
		logger.Info("scan requested")
		c.JSON(http.StatusAccepted, gin.H{
			"status": "scheduled",
		})
	})

	return r
}
