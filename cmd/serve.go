package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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

// bindHostEnv is the other way to say where the engine listens, and it is the SAME NAME the relay
// already reads to find the engine (LUMBERJACK_HOST in backend/.env.example), so one value in one
// file cannot describe two different addresses.
//
// It exists to make binding off-loopback possible, not easy: unset means 127.0.0.1, exactly as
// RELAY_HOST does for the relay in front of it. This host carries LAN, Tailscale and VPN addresses,
// and `Addr: ":" + port` used to hand the login route to all three with no TLS in front of it.
const bindHostEnv = "LUMBERJACK_HOST"

// resolveBindHost decides what gets bound: the flag, then the environment, then LOOPBACK. Whitespace
// is not an opt-in — a blank value is someone saying nothing, and saying nothing must never widen
// what is reachable.
func resolveBindHost(flagValue string) string {
	if host := strings.TrimSpace(flagValue); host != "" {
		return host
	}
	if host := strings.TrimSpace(os.Getenv(bindHostEnv)); host != "" {
		return host
	}
	return internal.LoopbackHost
}

// serveProcessInfo builds the record the server is started from, and is THE SEAM between the host
// this command resolved and the socket internal.ListenAddr opens.
//
// It is a function rather than a literal inside RunE because it is the one line in this file with
// no test above or below it that would catch its loss: the resolver can be right and the listener
// can be right while nothing carries the first to the second, and dropping BindHost here fails
// SAFE — every install keeps loopback, and --host and LUMBERJACK_HOST are silently ignored. That is
// the "feature removal rather than a default" the internal tests exist to prevent, arriving from
// the other side.
func serveProcessInfo(bindHost string) types.ProcessInfo {
	return types.ProcessInfo{
		ID:           "srv-" + serveDBName,
		PID:          os.Getpid(),
		Name:         serveDBName,
		ServerURL:    bindHost,
		BindHost:     bindHost,
		ServerPort:   servePort,
		LogPath:      serveLogDir,
		DatabasePath: serveDataDir,
	}
}

// warnIfExposed says so, loudly, when the address being bound is reachable from another machine.
// The engine speaks plain HTTP and sends no CORS headers, so an operator who did this by accident
// gets one chance to notice.
func warnIfExposed(host string) {
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return
	}
	fmt.Printf("[LumberJack] WARNING: binding %s, which is reachable off this machine. The API "+
		"speaks plain HTTP with no CORS allowlist; put a TLS terminator in front of it or bind "+
		"127.0.0.1 instead.\n", host)
}

var (
	serveHost      string
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
    lumberjack serve --port 8080 --db default --data-dir ./data/lumberjack

Binds 127.0.0.1 unless --host or LUMBERJACK_HOST says otherwise. The API speaks plain HTTP
with no CORS allowlist, so exposing it beyond loopback is a deliberate act.`,
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

		// Owner-only, and ENFORCED rather than merely requested. These two directories hold the
		// state file — every bcrypt hash on the server — and the log file that GET /logs serves.
		// They used to be made here at 0755, before anything with an opinion about the mode ran,
		// which is what made the 0700 in the state writer a no-op on every install.
		if err := types.EnsureDir(serveDataDir, types.DataDirMode); err != nil {
			return fmt.Errorf("failed to create data dir: %w", err)
		}
		if err := types.EnsureDir(serveLogDir, types.LogDirMode); err != nil {
			return fmt.Errorf("failed to create log dir: %w", err)
		}

		// Where it LISTENS, resolved once and then both bound and printed, so the line the
		// operator reads is the address the socket is actually on.
		bindHost := resolveBindHost(serveHost)
		warnIfExposed(bindHost)

		processInfo := serveProcessInfo(bindHost)

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

		fmt.Printf("[LumberJack] Ready and listening on http://%s (db: %s)\n",
			net.JoinHostPort(bindHost, servePort), serveDBName)

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
	serveCmd.Flags().StringVar(&serveHost, "host", "", "Address to bind (or "+bindHostEnv+"); "+
		"defaults to "+internal.LoopbackHost+". Anything else is reachable off this machine")
	serveCmd.Flags().StringVar(&serveDataDir, "data-dir", "./data/lumberjack", "Directory to store .dat files")
	serveCmd.Flags().StringVar(&serveLogDir, "log-dir", "./logs/lumberjack", "Directory for logs")
	serveCmd.Flags().StringVarP(&serveDBName, "db", "d", "default", "Database name")
	serveCmd.Flags().StringVar(&serveAdminUser, "admin-user", "admin", "Admin username for initialization")
	serveCmd.Flags().StringVar(&serveAdminPass, "admin-pass", "", "Admin password for initialization (or "+adminPassEnv+"); required on first init")
	serveCmd.Flags().StringVar(&serveAdminOrg, "admin-org", "Momentum", "Organization name")
	serveCmd.Flags().StringVar(&serveAdminMail, "admin-email", "admin@momentum.local", "Admin email")
}
