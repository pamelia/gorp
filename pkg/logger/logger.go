package logger

import (
	"go.uber.org/zap"
	"sync"
)

var (
	Logger *zap.Logger
	once   sync.Once
)

// InitLogger initializes the global logger
func InitLogger(level string, development bool) error {
	var err error
	once.Do(func() {
		var cfg zap.Config
		if development {
			cfg = zap.NewDevelopmentConfig()
		} else {
			cfg = zap.NewProductionConfig()
		}

		// Set the logging level
		if err = cfg.Level.UnmarshalText([]byte(level)); err != nil {
			return
		}

		Logger, err = cfg.Build()
		if err != nil {
			return
		}
	})
	return err
}

// Sync flushes any buffered log entries
func Sync() {
	if Logger != nil {
		_ = Logger.Sync()
	}
}
