package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/sovereign-eye/core/internal/messaging"
	"github.com/sovereign-eye/core/internal/orchestrator"
	"github.com/sovereign-eye/core/internal/storage"
	"github.com/sovereign-eye/core/pkg/config"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "sovereign-orchestrator",
	Short: "The Sovereign Eye Orchestrator",
	Long:  `Workflow orchestration engine for The Sovereign Eye platform`,
	RunE:  runOrchestrator,
}

func init() {
	cobra.OnInitialize(initConfig)
	
	rootCmd.PersistentFlags().String("config", "", "config file (default is ./configs/orchestrator.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Int("workers", 10, "number of workflow workers")
	rootCmd.PersistentFlags().Bool("enable-approvals", true, "enable workflow approval gates")
	
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("orchestrator.workers", rootCmd.PersistentFlags().Lookup("workers"))
	viper.BindPFlag("orchestrator.approvals.enabled", rootCmd.PersistentFlags().Lookup("enable-approvals"))
}

func initConfig() {
	if cfgFile := viper.GetString("config"); cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./configs")
		viper.SetConfigName("orchestrator")
		viper.SetConfigType("yaml")
	}
	
	viper.SetEnvPrefix("SOVEREIGN")
	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err == nil {
		logrus.Info("Using config file:", viper.ConfigFileUsed())
	}
}

func runOrchestrator(cmd *cobra.Command, args []string) error {
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
	}).Info("Starting Sovereign Eye Orchestrator")
	
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
	
	// Create orchestrator
	orchestratorEngine, err := orchestrator.New(orchestrator.Config{
		Workers:            viper.GetInt("orchestrator.workers"),
		EnableApprovals:    viper.GetBool("orchestrator.approvals.enabled"),
		MaxConcurrency:     viper.GetInt("orchestrator.max_concurrency"),
		TaskTimeout:        viper.GetDuration("orchestrator.task_timeout"),
		RetryAttempts:      viper.GetInt("orchestrator.retry_attempts"),
		RetryDelay:         viper.GetDuration("orchestrator.retry_delay"),
		RateLimitPerTenant: viper.GetInt("orchestrator.rate_limit.per_tenant"),
		RateLimitPerTarget: viper.GetInt("orchestrator.rate_limit.per_target"),
		RateLimitPerASN:    viper.GetInt("orchestrator.rate_limit.per_asn"),
	}, storageManager, messageBus, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create orchestrator")
	}
	
	// Start orchestrator
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	if err := orchestratorEngine.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start orchestrator")
	}
	
	logger.Info("Orchestrator started successfully")
	
	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	logger.Info("Shutting down orchestrator...")
	
	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	
	if err := orchestratorEngine.Stop(shutdownCtx); err != nil {
		logger.WithError(err).Error("Error during orchestrator shutdown")
		return err
	}
	
	logger.Info("Orchestrator shutdown complete")
	return nil
}

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
			semconv.ServiceNameKey.String("sovereign-orchestrator"),
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