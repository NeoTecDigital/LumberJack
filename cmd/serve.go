package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vaziolabs/lumberjack/internal"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// adminPassEnv is the other way to give the first admin a password. There is no third way: the
// flag used to default to "admin123", so every install that did not think about it came up with a
// published password on an admin account.
const adminPassEnv = "LUMBERJACK_ADMIN_PASS"

var (
	servePort      string
	serveDataDir   string
	serveLogDir    string
	serveDBName    string
	serveAdminUser string
	serveAdminPass string
	serveAdminOrg  string
	serveAdminMail string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start LumberJack API server directly in foreground",
	Long: `Start LumberJack API server directly without background daemonizing.
Ideal for development, Docker containers, and relay server integration.

Example:
    lumberjack serve --port 8080 --db default --data-dir ./data/lumberjack`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if serveDBName == "" {
			serveDBName = "default"
		}
		if serveDataDir == "" {
			serveDataDir = "./data/lumberjack"
		}
		if serveLogDir == "" {
			serveLogDir = "./logs/lumberjack"
		}
		if servePort == "" {
			servePort = "8080"
		}

		if serveAdminPass == "" {
			serveAdminPass = os.Getenv(adminPassEnv)
		}

		if err := os.MkdirAll(serveDataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data dir: %w", err)
		}
		if err := os.MkdirAll(serveLogDir, 0755); err != nil {
			return fmt.Errorf("failed to create log dir: %w", err)
		}

		processInfo := types.ProcessInfo{
			ID:           "srv-" + serveDBName,
			PID:          os.Getpid(),
			Name:         serveDBName,
			ServerURL:    "127.0.0.1",
			ServerPort:   servePort,
			LogPath:      serveLogDir,
			DatabasePath: serveDataDir,
		}

		serverConfig := types.ServerConfig{
			Organization: serveAdminOrg,
			Process:      processInfo,
		}

		dbPath := filepath.Join(serveDataDir, serveDBName+".dat")
		var server *internal.Server
		var err error

		if _, statErr := os.Stat(dbPath); statErr == nil {
			fmt.Printf("[LumberJack] Loading existing database '%s' from %s\n", serveDBName, dbPath)
			server, err = internal.LoadServer(serverConfig)
			if err != nil {
				return fmt.Errorf("failed to load database: %w", err)
			}
		} else {
			// FAIL CLOSED on first init. A password is required, and it is required HERE rather
			// than defaulted, because this is the only moment the account is created.
			if serveAdminPass == "" {
				return fmt.Errorf("no admin password: pass --admin-pass or set %s to initialize a new database", adminPassEnv)
			}

			fmt.Printf("[LumberJack] Initializing new database '%s' (admin: '%s') at %s\n", serveDBName, serveAdminUser, dbPath)
			adminUser := core.User{
				Username:     serveAdminUser,
				Password:     serveAdminPass,
				Organization: serveAdminOrg,
				Email:        serveAdminMail,
			}
			server, err = internal.NewServer(serverConfig, adminUser)
			if err != nil {
				return fmt.Errorf("failed to create new server: %w", err)
			}
		}

		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}

		fmt.Printf("[LumberJack] Ready and listening on http://127.0.0.1:%s (db: %s)\n", servePort, serveDBName)

		// Wait for shutdown signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n[LumberJack] Shutting down gracefully...")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&servePort, "port", "p", "8080", "Port to run API server on")
	serveCmd.Flags().StringVar(&serveDataDir, "data-dir", "./data/lumberjack", "Directory to store .dat files")
	serveCmd.Flags().StringVar(&serveLogDir, "log-dir", "./logs/lumberjack", "Directory for logs")
	serveCmd.Flags().StringVarP(&serveDBName, "db", "d", "default", "Database name")
	serveCmd.Flags().StringVar(&serveAdminUser, "admin-user", "admin", "Admin username for initialization")
	serveCmd.Flags().StringVar(&serveAdminPass, "admin-pass", "", "Admin password for initialization (or "+adminPassEnv+"); required on first init")
	serveCmd.Flags().StringVar(&serveAdminOrg, "admin-org", "Momentum", "Organization name")
	serveCmd.Flags().StringVar(&serveAdminMail, "admin-email", "admin@momentum.local", "Admin email")
}
