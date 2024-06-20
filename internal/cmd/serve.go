package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etherlabsio/healthcheck/v2"
	sentry2 "github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"

	"ely.by/profilecerts/internal/db/mysql"
	"ely.by/profilecerts/internal/db/redis"
	"ely.by/profilecerts/internal/http"
	"ely.by/profilecerts/internal/logging/sentry"
	"ely.by/profilecerts/internal/services/accounts"
	"ely.by/profilecerts/internal/services/authreader"
	"ely.by/profilecerts/internal/services/certmanager"
	"ely.by/profilecerts/internal/services/signer"
)

func Serve() error {
	config := initConfig()

	ctx := context.Background()
	ctx, _ = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, os.Kill)

	err := sentry.InitWithConfig(config)
	if err != nil {
		return fmt.Errorf("unable to initialize Sentry: %w", err)
	}
	defer sentry2.Flush(time.Second * 3)

	redis := redis.NewWithConfig(config)

	mysql, err := mysql.NewWithConfig(config)
	if err != nil {
		return fmt.Errorf("unable to initialize mysql: %w", err)
	}

	profilesCertificatesService := certmanager.New(redis)

	signerService, err := signer.NewLocalWithConfig(config)
	if err != nil {
		return fmt.Errorf("unable tot initialize signer: %w", err)
	}

	accountsApi, err := accounts.NewWithConfig(config)
	if err != nil {
		return fmt.Errorf("unable to initialize accounts api: %w", err)
	}

	authReader := authreader.NewElyby(accountsApi, mysql)

	if config.GetBool("debug") {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.Use(sentrygin.New(sentrygin.Options{Repanic: true}))
	r.Use(sentry.ErrorMiddleware())
	r.Use(http.ErrorMiddleware())

	r.GET("/healthcheck", gin.WrapH(healthcheck.Handler(
		healthcheck.WithChecker("redis", healthcheck.CheckerFunc(redis.Ping)),
		healthcheck.WithChecker("mysql", healthcheck.CheckerFunc(mysql.Ping)),
	)))

	sessionserver := http.NewProfileCertificatesApi(
		profilesCertificatesService,
		authReader,
		signerService,
	)
	sessionserver.DefineRoutes(r)

	server, err := http.NewServerWithConfig(config, r)
	if err != nil {
		return fmt.Errorf("unable to create a server: %w", err)
	}

	err = http.StartServer(ctx, server)
	if err != nil {
		return fmt.Errorf("unable to start a server: %w", err)
	}

	return nil
}
