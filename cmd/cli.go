package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vaziolabs/lumberjack/internal"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/internal/dashboard"
	"github.com/vaziolabs/lumberjack/types"
)

const (
	defaultLogDir  = "/var/log/lumberjack"
	defaultLibDir  = "/var/lib/lumberjack"
	defaultProcDir = "/etc/lumberjack"
)

var (
	configFile   string
	dashboardSet bool
	deleteAll    bool
	forceDelete  bool
	killAll      bool
	rootCmd      = &cobra.Command{
		Use:   "lumberjack",
		Short: "LumberJack - Event tracking and management system",
		Long: `LumberJack - Event tracking and management system

Directory Structure:
    Configs:     /etc/lumberjack/config.yaml
    Processes:   /etc/lumberjack/live/
    Logs:        /var/log/lumberjack/
    Data Files:  /var/lib/lumberjack/

Commands:
    create              Create a new configuration
    start [db-name]     Start server with optional database name
    list running        List all running servers
    list configs        List current configuration
    kill [server-id]    Kill a running server
    logs [server-id]    View server logs
    delete             Delete current configuration
    restart [server-id]  Restart a running server

Flags:
    -d, --dashboard    Start with dashboard enabled
    -c, --config       Specify config file to use`,
		Run: func(cmd *cobra.Command, args []string) {
			user := core.User{}
			if exists := configExists(); !exists {
				asciiArt, err := os.ReadFile("cmd/cli.ascii")
				if err == nil {
					fmt.Println(string(asciiArt))
				}
				createConfig(cmd, args)
			} else {
				// Get target database name
				dbName := "default"
				if len(args) > 0 {
					dbName = args[0]
				}

				processes, err := getRunningServers()
				if err != nil {
					fmt.Printf("Error getting running servers: %v\n", err)
					os.Exit(1)
				}

				// Find the specific server by database name
				var targetProcess *types.ProcessInfo
				for _, p := range processes {
					if p.Name == dbName {
						targetProcess = &p
						break
					}
				}

				if targetProcess != nil {
					config := loadConfig(targetProcess.Name)

					// Server already running, just start dashboard if requested
					if dashboardSet && !targetProcess.DashboardUp {
						apiEndpoint := fmt.Sprintf("http://%s:%s", config.ServerURL, config.ServerPort)
						dash := dashboard.NewDashboard(apiEndpoint, config.DashboardPort)
						if err := dash.Start(); err != nil {
							fmt.Printf("Error starting dashboard: %v\n", err)
							os.Exit(1)
						}
						targetProcess.DashboardUp = true
						updateProcessInfo(*targetProcess)
						fmt.Printf("%s LumberJack server running on http://%s:%s\n", dbName, config.ServerURL, config.ServerPort)
						fmt.Printf("%s LumberJack dashboard starting on http://%s:%s\n", dbName, config.ServerURL, config.DashboardPort)
					} else {
						fmt.Printf("%s LumberJack server running on http://%s:%s\n", dbName, config.ServerURL, config.ServerPort)
						if targetProcess.DashboardUp {
							fmt.Printf("%s LumberJack dashboard running on http://%s:%s\n", dbName, config.ServerURL, config.DashboardPort)
						}
					}
				} else {
					startServer(cmd, args, user)
				}
			}
		},
	}
	listCmd = &cobra.Command{
		Use:   "list [running|configs]",
		Short: "List running servers or configurations",
		Long: `List running servers or view current configuration.

Example:
    lumberjack list running
    lumberjack list configs`,
		Run: listHandler,
	}
	deleteCmd = &cobra.Command{
		Use:   "delete [database-name]",
		Short: "Delete configuration",
		Long: `Delete a database configuration.
Requires database name unless --all flag is provided.
Use --force to skip confirmation prompt.

Example:
    lumberjack delete mydb
    lumberjack delete --all
    lumberjack delete --all --force`,
		Run: deleteConfig,
	}
	killCmd = &cobra.Command{
		Use:   "kill [server-id]",
		Short: "Kill a running server",
		Long: `Kill a running server by its ID.
Use 'list running' to see available server IDs.
Use -d flag to kill only the dashboard.
Use --all to kill all running servers.
Use --force to skip confirmation prompt.

Example:
    lumberjack kill abc123xyz
    lumberjack kill abc123xyz -d
    lumberjack kill --all
    lumberjack kill --all --force`,
		Run: killServer,
	}
	logsCmd = &cobra.Command{
		Use:   "logs [server-id]",
		Short: "View server logs",
		Long: `View logs for a specific server by its ID.
Use 'list running' to see available server IDs.

Example:
    lumberjack logs abc123xyz`,
		Run: viewLogs,
	}
	restartCmd = &cobra.Command{
		Use:   "restart [server-id]",
		Short: "Restart a running server",
		Long: `Restart a running server by its ID.
If no ID is provided and only one server exists, it will be restarted.
The dashboard will be restarted if it was running.

Example:
    lumberjack restart
    lumberjack restart abc123xyz`,
		Run: restartServer,
	}
)

func init() {
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(killCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(restartCmd)

	createCmd.AddCommand(newHelpCmd(createCmd))
	startCmd.AddCommand(newHelpCmd(startCmd))
	listCmd.AddCommand(newHelpCmd(listCmd))
	deleteCmd.AddCommand(newHelpCmd(deleteCmd))
	killCmd.AddCommand(newHelpCmd(killCmd))
	logsCmd.AddCommand(newHelpCmd(logsCmd))
	restartCmd.AddCommand(newHelpCmd(restartCmd))

	startCmd.Flags().BoolVarP(&dashboardSet, "dashboard", "d", false, "Start with dashboard")
	startCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file to use")

	killCmd.Flags().BoolVarP(&dashboardSet, "dashboard", "d", false, "Kill only the dashboard")
	killCmd.Flags().BoolVar(&killAll, "all", false, "Kill all running servers")
	killCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force kill without confirmation")

	deleteCmd.Flags().BoolVar(&deleteAll, "all", false, "Delete all configurations")
	deleteCmd.Flags().BoolVar(&forceDelete, "force", false, "Force delete without confirmation")

	logsCmd.Flags().IntP("lines", "n", 0, "Number of lines to show from the end")
	logsCmd.Flags().BoolP("follow", "f", false, "Follow log output")

	rootCmd.Flags().BoolVarP(&dashboardSet, "dashboard", "d", false, "Start with dashboard")

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !configExists() {
			asciiArt, err := os.ReadFile("cmd/cli.ascii")
			if err == nil {
				fmt.Println(string(asciiArt))
			}
			return createConfig(cmd, args)
		}
		return cmd.Help()
	}
}

var createCmd = &cobra.Command{
	Use:   "create [config-name]",
	Short: "Create a new LumberJack configuration",
	Long: `Create a new LumberJack configuration file.
If no config name is provided, 'default' will be used.

Example:
    lumberjack create
    lumberjack create myconfig`,
	RunE: createConfig,
}

var startCmd = &cobra.Command{
	Use:   "start [database-name]",
	Short: "Start LumberJack server",
	Long: `Start LumberJack server with optional database name.
Use -d flag to start with dashboard enabled.

Example:
    lumberjack start
    lumberjack start mydb
    lumberjack start -d
    lumberjack start mydb -d`,
	Run: func(cmd *cobra.Command, args []string) {
		// If this is a spawned process, run the server directly
		if os.Getenv("LUMBERJACK_SPAWNED") == "1" {
			runServer(cmd, args)
			return
		}

		// Otherwise, spawn a new process
		dbName := "default"
		if len(args) > 0 {
			dbName = args[0]
		}

		config := loadConfig(dbName)
		if err := spawnServer(config, dashboardSet); err != nil {
			fmt.Printf("Error spawning server: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("LumberJack %s server started in background\n", dbName)
		if dashboardSet {
			fmt.Printf("Dashboard available at http://%s:%s\n", config.ServerURL, config.DashboardPort)
		}
	},
}

func runServer(cmd *cobra.Command, args []string) {
	dbName := "default"
	if len(args) > 0 {
		dbName = args[0]
	}

	var processInfo types.ProcessInfo

	// First try to get config from environment (passed by spawner)
	if configJSON := os.Getenv("LUMBERJACK_CONFIG"); configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &processInfo); err != nil {
			fmt.Printf("Error parsing config from environment: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Fallback: try to load from file system
		config := loadConfig(dbName)

		// Get the process info first
		processes, err := getRunningServers()
		if err != nil {
			fmt.Printf("Error getting process info: %v\n", err)
			os.Exit(1)
		}

		// Find the process for this database
		var found bool
		for _, p := range processes {
			if p.Name == dbName {
				processInfo = p
				found = true
				break
			}
		}

		if !found {
			// If not found in running processes, create new processInfo from config
			processInfo = config
		}
	}

	// Update paths in process info
	processInfo.DatabasePath = filepath.Join(defaultLibDir, dbName)
	processInfo.LogPath = defaultLogDir

	serverConfig := types.ServerConfig{
		Process: processInfo,
	}

	server, err := internal.LoadServer(serverConfig)
	if err != nil {
		// If database doesn't exist yet, create a new one
		if os.IsNotExist(err) {
			// Create admin user from config
			user := core.User{}
			if processInfo.Admin != nil {
				user = core.User{
					ID:           fmt.Sprintf("user-%d", time.Now().Unix()),
					Name:         processInfo.Admin.Organization,
					Username:     processInfo.Admin.Username,
					Email:        processInfo.Admin.Email,
					Password:     processInfo.Admin.Password,
					Organization: processInfo.Admin.Organization,
					Phone:        processInfo.Admin.Phone,
					Permissions:  []core.Permission{core.AdminPermission},
				}
			}
			server, err = internal.NewServer(serverConfig, user)
			if err != nil {
				fmt.Printf("Error creating new server: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Error loading server: %v\n", err)
			os.Exit(1)
		}
	}

	if err := server.Start(); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		os.Exit(1)
	}

	if dashboardSet || processInfo.DashboardUp {
		apiEndpoint := fmt.Sprintf("http://%s:%s", processInfo.ServerURL, processInfo.ServerPort)
		dash := dashboard.NewDashboard(apiEndpoint, processInfo.DashboardPort)
		dash.Start()
	}

	select {}
}

func createConfig(cmd *cobra.Command, args []string) error {
	// Check if config file exists and load it if it does
	var config types.Config
	configFile := filepath.Join(defaultProcDir, "config.yaml")

	if _, err := os.Stat(configFile); err == nil {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(defaultProcDir)

		if err := viper.ReadInConfig(); err != nil {
			fmt.Printf("Error reading existing config: %v\n", err)
			os.Exit(1)
		}

		if err := viper.Unmarshal(&config); err != nil {
			fmt.Printf("Error parsing existing config: %v\n", err)
			os.Exit(1)
		}
	} else {
		config = types.Config{
			Version:   "0.1.1-alpha",
			Databases: make(map[string]types.ProcessInfo),
		}
	}

	dbConfig := types.ProcessInfo{
		ServerURL:     "localhost",
		ServerPort:    "8080",
		DashboardPort: "8081",
		Name:          "",
	}

	// Get database name
	defaultDbName := "default"
	if len(args) > 0 {
		defaultDbName = args[0]
	}

	prompt := promptui.Prompt{
		Label:    "LumberJack Database Name",
		Default:  defaultDbName,
		Validate: validateDBName,
	}

	dbName, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		os.Exit(1)
	}

	// Check if database already exists
	if _, exists := config.Databases[dbName]; exists {
		fmt.Printf("Database %s already exists\n", dbName)
		os.Exit(1)
	}

	user := core.User{
		Username:     "admin",
		Password:     "admin",
		Organization: "LumberJack",
		Phone:        "1234567890",
		Email:        "admin@lumberjack.com",
	}

	prompts := []struct {
		label    string
		field    *string
		default_ string
	}{
		{"Organization", &user.Organization, "LumberJack"},
		{"Email (optional):", &user.Email, ""},
		{"Phone Number (optional):", &user.Phone, ""},
		{"Admin Username", &user.Username, user.Username},
		{"Admin Password", &user.Password, user.Password},
		{"Re-enter Admin Password", &user.Password, user.Password},
		{"LumberJack Host Domain", &dbConfig.ServerURL, "localhost"},
		{"LumberJack API Port", &dbConfig.ServerPort, "8080"},
		{"LumberJack Dashboard Port", &dbConfig.DashboardPort, "8081"},
	}

	for i, p := range prompts {
		prompt := promptui.Prompt{
			Label:   p.label,
			Default: p.default_,
		}
		if strings.Contains(strings.ToLower(p.label), "password") {
			prompt.Mask = '*'
		}
		result, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed: %v\n", err)
			os.Exit(1)
		}

		if i == 5 {
			if result != prompts[4].default_ {
				fmt.Println("Passwords do not match")
				os.Exit(1)
			}
		}

		*p.field = result
	}

	if user.Password != prompts[5].default_ {
		user.Username = prompts[4].default_
		user.Password = prompts[5].default_
	}

	dbConfig.Name = dbName
	config.Databases[dbName] = dbConfig

	// Save updated config
	viper.Set("version", config.Version)
	viper.Set("databases", config.Databases)

	if err := os.MkdirAll(defaultProcDir, 0755); err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	if err := viper.WriteConfigAs(configFile); err != nil {
		fmt.Printf("Error writing config: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Join(defaultLibDir, dbName), 0755); err != nil {
		fmt.Printf("Error creating database directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration created successfully!")

	// Create initial server to save admin info
	serverConfig := types.ServerConfig{
		Process: types.ProcessInfo{
			Name:          dbName,
			ServerURL:     dbConfig.ServerURL,
			ServerPort:    dbConfig.ServerPort,
			DashboardURL:  dbConfig.ServerURL,
			DashboardPort: dbConfig.DashboardPort,
			LogPath:       defaultLogDir,
			DatabasePath:  defaultLibDir,
		},
	}

	// Initialize server just to save admin info
	_, err = internal.NewServer(serverConfig, user)
	if err != nil {
		fmt.Printf("Error creating server: %v\n", err)
		os.Exit(1)
	}

	return nil
}

func killServer(cmd *cobra.Command, args []string) {
	defer os.Exit(0) // Ensure we exit after handling

	if !killAll && len(args) == 0 {
		fmt.Println("Server name or ID required")
		os.Exit(1)
		return
	}

	processes, err := getRunningServers()
	if err != nil {
		fmt.Printf("Error getting running servers: %v\n", err)
		os.Exit(1)
		return
	}

	if killAll {
		if len(processes) == 0 {
			fmt.Println("No running servers found")
			return
		}
		if !forceDelete {
			fmt.Println("Warning: This action will kill all running servers.")
			fmt.Print("Are you sure you want to kill ALL servers? [y/N]: ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Operation cancelled")
				return
			}
		}

		for _, proc := range processes {
			if err := killProcess(proc); err != nil {
				fmt.Printf("Warning: Error killing process %s: %v\n", proc.ID, err)
			}
		}
		fmt.Println("All servers killed successfully")
		return
	}

	var proc types.ProcessInfo
	found := false
	for _, p := range processes {
		if p.ID == args[0] || p.Name == args[0] {
			proc = p
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("Server %s not found\n", args[0])
		return
	}

	if err := killProcess(proc); err != nil {
		fmt.Printf("Error killing process: %v\n", err)
		return
	}

	fmt.Printf("Server %s killed successfully\n", args[0])
}

func viewLogs(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Println("Server ID required")
		return
	}

	processes, err := getRunningServers()
	if err != nil {
		fmt.Printf("Error getting running servers: %v\n", err)
		return
	}

	var proc types.ProcessInfo
	found := false
	for _, p := range processes {
		if p.ID == args[0] {
			proc = p
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("Server %s not found\n", args[0])
		return
	}

	logFile := filepath.Join(defaultLogDir, fmt.Sprintf("lumberjack-%s.log", proc.ID))
	if _, err := os.Stat(logFile); err != nil {
		fmt.Printf("Log file not found: %v\n", err)
		return
	}

	lines, _ := cmd.Flags().GetInt("lines")
	follow, _ := cmd.Flags().GetBool("follow")

	if follow {
		tailFile(logFile)
		return
	}

	if lines > 0 {
		showLastLines(logFile, lines)
		return
	}

	// Show entire file if no flags specified
	content, err := os.ReadFile(logFile)
	if err != nil {
		fmt.Printf("Error reading log file: %v\n", err)
		return
	}
	fmt.Print(string(content))
}

func tailFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	// Seek to end of file
	file.Seek(0, 2)

	for {
		buffer := make([]byte, 1024)
		n, err := file.Read(buffer)
		if err != nil && err.Error() != "EOF" {
			fmt.Printf("Error reading file: %v\n", err)
			return
		}
		if n > 0 {
			fmt.Print(string(buffer[:n]))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func showLastLines(filename string, n int) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}

	for _, line := range lines {
		fmt.Println(line)
	}
}

func listHandler(cmd *cobra.Command, args []string) {
	defer os.Exit(0) // Ensure we exit after handling

	if len(args) == 0 || args[0] == "configs" {
		listConfig(cmd, args)
		return
	}

	if args[0] == "running" {
		listRunning()
		return
	}

	fmt.Println("Invalid argument. Use 'running' or 'configs'")
}

func listRunning() {
	processes, err := getRunningServers()
	if err != nil {
		fmt.Printf("Error getting running servers: %v\n", err)
		return
	}

	if len(processes) == 0 {
		fmt.Println("No running servers found")
		return
	}

	fmt.Println("Running Servers:")
	for _, p := range processes {
		liveFilePath := filepath.Join("/etc/lumberjack/live", p.ID)
		status := "Not Running"
		if _, err := os.Stat(liveFilePath); err == nil {
			status = "Running"
		}

		fmt.Printf("ID: %s | Name: %s | API Port: %s | Dashboard Port: %s | Status: %s\n",
			p.ID, p.Name, p.ServerPort, p.DashboardPort, status)
	}
}

func listConfig(cmd *cobra.Command, args []string) {
	configDir := getConfigDir()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("No configuration found: %v\n", err)
		return
	}

	var config types.Config
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		return
	}

	// Get running servers to check status
	runningServers, err := getRunningServers()
	if err != nil {
		fmt.Printf("Error getting running servers: %v\n", err)
		return
	}

	fmt.Printf("%-20s %-10s %-20s %-10s\n", "Name", "API Port", "Dashboard Port", "Status")
	fmt.Println(strings.Repeat("-", 60))

	for name, db := range config.Databases {
		apiPort := db.ServerPort
		dashPort := db.DashboardPort
		status := "Not Running"

		for _, proc := range runningServers {
			if proc.Name == name {
				if proc.DashboardUp {
					dashPort = fmt.Sprintf("%s (Running)", db.DashboardPort)
				}
				status = fmt.Sprintf("Running (%s)", proc.ID)
				break
			}
		}

		fmt.Printf("%-20s %-10s %-20s %-10s\n",
			name,
			apiPort,
			dashPort,
			status)
	}
}

func newHelpCmd(parent *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help",
		Short: fmt.Sprintf("Help about the %s command", parent.Name()),
		Long:  parent.Long,
		Run: func(cmd *cobra.Command, args []string) {
			parent.Help()
		},
	}
}

func startServer(cmd *cobra.Command, args []string, user core.User) {
	dbName := "default"
	if len(args) > 0 {
		dbName = args[0]
	}

	// Get dashboard flag from root command if not set
	if !dashboardSet {
		dashboardSet, _ = cmd.Flags().GetBool("dashboard")
	}

	config := loadConfig(dbName)
	if err := spawnServer(config, dashboardSet); err != nil {
		fmt.Printf("Error spawning server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("LumberJack %s server started at http://%s:%s\n", dbName, config.ServerURL, config.ServerPort)
	if dashboardSet {
		fmt.Printf("Dashboard available at http://%s:%s\n", config.ServerURL, config.DashboardPort)
	}
}

func restartServer(cmd *cobra.Command, args []string) {
	processes, err := getRunningServers()
	if err != nil {
		fmt.Printf("Error getting running servers: %v\n", err)
		return
	}

	if len(processes) == 0 {
		fmt.Println("No running servers found")
		return
	}

	var proc types.ProcessInfo
	if len(args) == 0 {
		if len(processes) > 1 {
			fmt.Println("Multiple servers running, please specify server ID")
			return
		}
		proc = processes[0]
	} else {
		found := false
		for _, p := range processes {
			if p.ID == args[0] {
				proc = p
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Server %s not found\n", args[0])
			return
		}
	}

	// Kill existing server
	process, err := os.FindProcess(proc.PID)
	if err != nil {
		fmt.Printf("Error finding process: %v\n", err)
		return
	}

	if err := process.Kill(); err != nil {
		fmt.Printf("Error killing process: %v\n", err)
		return
	}

	if err := removeProcess(proc.ID); err != nil {
		fmt.Printf("Error removing process from tracking: %v\n", err)
		return
	}

	// Start new server
	config := loadConfig(proc.Name)
	if err := spawnServer(config, proc.DashboardUp); err != nil {
		fmt.Printf("Error spawning server: %v\n", err)
		return
	}

	fmt.Printf("Server %s restarted successfully\n", proc.Name)
	if proc.DashboardUp {
		fmt.Printf("Dashboard restarted at http://%s:%s\n", config.ServerURL, config.DashboardPort)
	}
}

// Add this function to handle database name validation
func validateDBName(input string) error {
	if len(input) < 1 {
		return fmt.Errorf("database name cannot be empty")
	}
	// Add any other validation rules you need
	return nil
}
