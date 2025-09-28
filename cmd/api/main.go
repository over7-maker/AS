package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/sovereign-eye/core/internal/auth"
	"github.com/sovereign-eye/core/internal/controller"
	"github.com/sovereign-eye/core/internal/messaging"
	"github.com/sovereign-eye/core/internal/storage"
	"github.com/sovereign-eye/core/pkg/config"
	"github.com/sovereign-eye/core/pkg/middleware"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "sovereign-api",
	Short: "The Sovereign Eye API Server",
	Long:  `API server for The Sovereign Eye - RPKI-Secured & Graph-Driven ASM Core`,
	RunE:  runServer,
}

func init() {
	cobra.OnInitialize(initConfig)
	
	rootCmd.PersistentFlags().String("config", "", "config file (default is ./configs/api.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Int("port", 8080, "API server port")
	rootCmd.PersistentFlags().Bool("enable-tls", false, "Enable TLS/HTTPS")
	
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("server.port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("server.tls.enabled", rootCmd.PersistentFlags().Lookup("enable-tls"))
}

func initConfig() {
	if cfgFile := viper.GetString("config"); cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./configs")
		viper.SetConfigName("api")
		viper.SetConfigType("yaml")
	}
	
	viper.SetEnvPrefix("SOVEREIGN")
	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err == nil {
		logrus.Info("Using config file:", viper.ConfigFileUsed())
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})
	
	logger.WithFields(logrus.Fields{
		"version":   version,
		"buildDate": buildDate,
		"gitCommit": gitCommit,
	}).Info("Starting Sovereign Eye API Server")
	
	// Initialize tracing
	ctx := context.Background()
	tp, err := initTracer(ctx)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize tracer")
	} else {
		defer func() {
			if err := tp.Shutdown(ctx); err != nil {
				logger.WithError(err).Error("Failed to shutdown tracer")
			}
		}()
	}
	
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}
	
	// Initialize storage
	storageManager, err := storage.NewManager(cfg.Storage)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize storage")
	}
	defer storageManager.Close()
	
	// Initialize message bus
	messageBus, err := messaging.NewBus(cfg.Messaging)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize message bus")
	}
	defer messageBus.Close()
	
	// Initialize authentication
	authManager, err := auth.NewManager(cfg.Auth, storageManager)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize authentication")
	}
	
	// Initialize controllers
	mainController := controller.New(cfg, storageManager, messageBus, authManager, logger)
	
	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	
	// Add middleware
	router.Use(middleware.Logger(logger))
	router.Use(middleware.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.RateLimiter())
	router.Use(middleware.Metrics())
	router.Use(middleware.Tracing())
	
	// Health check endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": version,
			"uptime":  time.Since(startTime).String(),
		})
	})
	
	router.GET("/ready", func(c *gin.Context) {
		if err := storageManager.Health(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"error":  err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	
	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// API routes
	v1 := router.Group("/api/v1")
	v1.Use(middleware.Authentication(authManager))
	{
		// Asset management
		v1.POST("/assets", mainController.CreateAsset)
		v1.GET("/assets", mainController.ListAssets)
		v1.GET("/assets/:id", mainController.GetAsset)
		v1.PUT("/assets/:id", mainController.UpdateAsset)
		v1.DELETE("/assets/:id", mainController.DeleteAsset)
		
		// Workflow management
		v1.POST("/workflows", mainController.CreateWorkflow)
		v1.GET("/workflows", mainController.ListWorkflows)
		v1.GET("/workflows/:id", mainController.GetWorkflow)
		v1.PUT("/workflows/:id", mainController.UpdateWorkflow)
		v1.DELETE("/workflows/:id", mainController.DeleteWorkflow)
		v1.POST("/workflows/:id/execute", mainController.ExecuteWorkflow)
		v1.POST("/workflows/:id/approve", mainController.ApproveWorkflow)
		
		// Scan management
		v1.POST("/scans", mainController.CreateScan)
		v1.GET("/scans", mainController.ListScans)
		v1.GET("/scans/:id", mainController.GetScan)
		v1.GET("/scans/:id/results", mainController.GetScanResults)
		v1.POST("/scans/:id/cancel", mainController.CancelScan)
		
		// Findings
		v1.GET("/findings", mainController.ListFindings)
		v1.GET("/findings/:id", mainController.GetFinding)
		v1.PUT("/findings/:id", mainController.UpdateFinding)
		v1.POST("/findings/:id/remediate", mainController.RemediateFinding)
		
		// Attack paths
		v1.GET("/attack-paths", mainController.GetAttackPaths)
		v1.GET("/attack-paths/:id", mainController.GetAttackPath)
		v1.POST("/attack-paths/analyze", mainController.AnalyzeAttackPaths)
		
		// Risk scoring
		v1.GET("/risk-scores", mainController.GetRiskScores)
		v1.GET("/risk-scores/:asset_id", mainController.GetAssetRiskScore)
		v1.POST("/risk-scores/calculate", mainController.CalculateRiskScores)
		
		// Compliance reporting
		v1.GET("/compliance/reports", mainController.ListComplianceReports)
		v1.POST("/compliance/reports/generate", mainController.GenerateComplianceReport)
		v1.GET("/compliance/frameworks", mainController.ListComplianceFrameworks)
		
		// Tenant management
		v1.POST("/tenants", mainController.CreateTenant)
		v1.GET("/tenants", mainController.ListTenants)
		v1.GET("/tenants/:id", mainController.GetTenant)
		v1.PUT("/tenants/:id", mainController.UpdateTenant)
		v1.DELETE("/tenants/:id", mainController.DeleteTenant)
		
		// Admin endpoints
		admin := v1.Group("/admin")
		admin.Use(middleware.RequireAdmin())
		{
			admin.GET("/stats", mainController.GetSystemStats)
			admin.POST("/maintenance", mainController.SetMaintenanceMode)
			admin.GET("/config", mainController.GetConfiguration)
			admin.PUT("/config", mainController.UpdateConfiguration)
		}
	}
	
	// WebSocket endpoint for real-time updates
	router.GET("/ws", mainController.WebSocketHandler)
	
	// Start server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", viper.GetInt("server.port")),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()
	
	logger.Infof("API server started on port %d", viper.GetInt("server.port"))
	
	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	logger.Info("Shutting down server...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
		return err
	}
	
	logger.Info("Server shutdown complete")
	return nil
}

var startTime = time.Now()

func initTracer(ctx context.Context) (*trace.TracerProvider, error) {
	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(
			jaeger.WithEndpoint(viper.GetString("tracing.jaeger.endpoint")),
		),
	)
	if err != nil {
		return nil, err
	}
	
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("sovereign-api"),
			semconv.ServiceVersionKey.String(version),
		)),
	)
	
	otel.SetTracerProvider(tp)
	return tp, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}