package main

import (
	"github.com/pamelia/gorp/cmd"
	"github.com/pamelia/gorp/pkg/logger"
	"log"
)

func main() {
	// Initialize the logger
	err := logger.InitLogger("info", false) // Adjust level and development mode as needed
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	cmd.Execute()
}
