package types

// AdminConfig holds admin user configuration
type AdminConfig struct {
	Username     string `yaml:"username" json:"username"`
	Email        string `yaml:"email" json:"email"`
	Password     string `yaml:"password" json:"password"`
	Organization string `yaml:"organization" json:"organization"`
	Phone        string `yaml:"phone" json:"phone"`
}

type ProcessInfo struct {
	ID            string       `json:"id" yaml:"id"`
	PID           int          `json:"pid" yaml:"pid"`
	Name          string       `json:"name" yaml:"name"`
	ServerURL     string       `json:"server_url" yaml:"serverurl"`
	ServerPort    string       `json:"server_port" yaml:"serverport"`
	DashboardPort string       `json:"dashboard_port" yaml:"dashboardport"`
	DashboardURL  string       `json:"dashboard_url,omitempty" yaml:"dashboardurl,omitempty"`
	DashboardUp   bool         `json:"dashboard_up" yaml:"dashboardup"`
	LogPath       string       `json:"log_path" yaml:"logpath"`
	DatabasePath  string       `json:"database_path" yaml:"databasepath"`
	Organization  string       `json:"organization,omitempty" yaml:"organization,omitempty"`
	Phone         string       `json:"phone,omitempty" yaml:"phone,omitempty"`
	Admin         *AdminConfig `json:"admin,omitempty" yaml:"admin,omitempty"`
}

type Config struct {
	Version   string                 `yaml:"version"`
	Databases map[string]ProcessInfo `yaml:"databases"`
}

type ServerConfig struct {
	Organization string      `json:"organization"`
	Phone        string      `json:"phone,omitempty"`
	Process      ProcessInfo `json:"process"`
}
