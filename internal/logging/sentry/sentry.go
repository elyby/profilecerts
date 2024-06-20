package sentry

import (
	"github.com/getsentry/sentry-go"
	sentryGin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"ely.by/profilecerts/internal/version"
)

func InitWithConfig(config *viper.Viper) error {
	config.SetDefault("sentry.enable_tracing", false)
	config.SetDefault("sentry.traces_sample_rate", 1.0)

	sampleRate := config.GetFloat64("sentry.traces_sample_rate")

	return sentry.Init(sentry.ClientOptions{
		Dsn:           config.GetString("sentry.dsn"),
		EnableTracing: config.GetBool("sentry.enable_tracing"),
		TracesSampler: func(ctx sentry.SamplingContext) float64 {
			if ctx.Span.Name == "GET /healthcheck" {
				return 0
			}

			return sampleRate
		},
		Release:     version.Version(),
		Environment: config.GetString("sentry.environment"),
		Integrations: func(integrations []sentry.Integration) []sentry.Integration {
			nDeleted := 0
			for i, integration := range integrations {
				if integration.Name() == "Modules" {
					integrations[i] = integrations[len(integrations)-(nDeleted+1)]
					nDeleted++
				}
			}

			return integrations[:len(integrations)-nDeleted]
		},
	})
}

// It seems like this must be a part of the sentrygin package, but it is not, so implement it ourselves
func ErrorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sentryHub := sentryGin.GetHubFromContext(c)
		if sentryHub != nil {
			return
		}

		for _, err := range c.Errors {
			sentryHub.CaptureException(err)
		}
	}
}
