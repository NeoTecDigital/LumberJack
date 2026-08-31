package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vaziolabs/lumberjack/types"
	"golang.org/x/exp/rand"
)

func generateID() string {
	const (
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		length  = 16
	)

	for {
		result := make([]byte, length)
		for i := range result {
			result[i] = charset[rand.Intn(len(charset))]
		}

		id := string(result)
		// Check if ID already exists in live process directory
		if _, err := os.Stat(filepath.Join(defaultProcDir, "live", id)); os.IsNotExist(err) {
			return id
		} else {
			// Retry if ID already exists
			return generateID()
		}
	}
}

func deleteConfig(cmd *cobra.Command, args []string) {
	if !deleteAll && len(args) == 0 {
		fmt.Println("Error: database name required unless --all flag is provided")
		return
	}

	if deleteAll {
		// Kill all running servers first
		processes, err := getRunningServers()
		if err != nil {
			fmt.Printf("Error getting running servers: %v\n", err)
			return
		}

		// Kill all running servers
		for _, proc := range processes {
			if err := killProcess(proc); err != nil {
				fmt.Printf("Warning: Error killing process %s: %v\n", proc.ID, err)
			} else {
				fmt.Printf("Killing %s lumberjack server - process %s\n.", proc.Name, proc.ID)
			}
		}

		if !forceDelete {
			fmt.Println("Warning: This action is irreversible and will delete all databases and associated logs.")
			fmt.Print("Are you sure you want to delete ALL configurations? [y/N]: ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Operation cancelled")
				return
			}
		}

		// Clean up /var/lib/lumberjack
		if err := os.RemoveAll(defaultLibDir); err != nil {
			fmt.Printf("Error cleaning up %s: %v\n", defaultLibDir, err)
		}
		if err := types.EnsureDir(defaultLibDir, types.DataDirMode); err != nil {
			fmt.Printf("Error recreating %s: %v\n", defaultLibDir, err)
		}

		// Clean up /var/log/lumberjack
		if err := os.RemoveAll(defaultLogDir); err != nil {
			fmt.Printf("Error cleaning up %s: %v\n", defaultLogDir, err)
		}
		if err := types.EnsureDir(defaultLogDir, types.LogDirMode); err != nil {
			fmt.Printf("Error recreating %s: %v\n", defaultLogDir, err)
		}

		// Clean up /etc/lumberjack/live
		liveDir := filepath.Join(defaultProcDir, "live")
		if err := os.RemoveAll(liveDir); err != nil {
			fmt.Printf("Error cleaning up %s: %v\n", liveDir, err)
		}
		if err := os.MkdirAll(liveDir, 0755); err != nil {
			fmt.Printf("Error recreating %s: %v\n", liveDir, err)
		}

		// Delete config file - ignore if it doesn't exist
		configFile := filepath.Join(defaultProcDir, "config.yaml")
		_ = os.Remove(configFile)

		fmt.Println("All configurations and associated files deleted successfully")
		return
	}

	// For single database deletion, we need the config file to exist
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(defaultProcDir)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("No configuration found: %v\n", err)
		return
	}

	var config types.Config
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		return
	}

	dbName := args[0]
	if _, exists := config.Databases[dbName]; !exists {
		fmt.Printf("Database '%s' not found in configuration\n", dbName)
		return
	}

	if !forceDelete {
		fmt.Println("Warning: This action is irreversible and will delete the database and all associated logs.")
		fmt.Printf("Are you sure you want to delete database '%s'? [y/N]: ", dbName)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled")
			return
		}
	}

	// Delete database directory
	dbPath := filepath.Join(defaultLibDir, dbName)
	if err := os.RemoveAll(dbPath); err != nil {
		fmt.Printf("Error deleting database files for %s: %v\n", dbName, err)
	}

	// Delete log directory
	logPath := filepath.Join(defaultLogDir, dbName)
	if err := os.RemoveAll(logPath); err != nil {
		fmt.Printf("Error deleting logs for %s: %v\n", dbName, err)
	}

	// Delete .dat file
	datFile := filepath.Join(defaultLibDir, dbName+".dat")
	if err := os.Remove(datFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("Error deleting database file for %s: %v\n", dbName, err)
	}

	delete(config.Databases, dbName)
	if err := saveConfig(config); err != nil {
		fmt.Printf("Error saving configuration: %v\n", err)
		return
	}
	fmt.Printf("Database '%s' configuration and files deleted successfully\n", dbName)
}

func saveConfig(config types.Config) error {
	viper.Set("version", config.Version)
	viper.Set("databases", config.Databases)
	return viper.WriteConfig()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func configExists() bool {
	_, err := os.Stat(filepath.Join(defaultProcDir, "config.yaml"))
	return err == nil
}

func getConfigDir() string {
	return defaultProcDir
}

func loadConfig(dbName string) types.ProcessInfo {
	configDir := getConfigDir()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		os.Exit(1)
	}

	var config types.Config
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		os.Exit(1)
	}

	dbConfig, exists := config.Databases[dbName]
	if !exists {
		fmt.Printf("Database %s not found in config\n", dbName)
		os.Exit(1)
	}

	return dbConfig
}

func updateProcessInfo(proc types.ProcessInfo) error {
	data, err := json.Marshal(proc)
	if err != nil {
		return fmt.Errorf("failed to marshal process info: %v", err)
	}

	processFile := getProcessFilePath(proc.ID)
	return os.WriteFile(processFile, data, 0644)
}
