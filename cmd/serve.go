package cmd

import (
	"github.com/pamelia/gorp/pkg/proxy"
	"log"

	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the proxy server",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, err := cmd.PersistentFlags().GetString("config")
		if err != nil {
			log.Fatalf("Error getting config flag: %v", err)
		}

		proxy.Start(configPath)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringP("config", "c", "config.yaml", "Path to config file")
}
