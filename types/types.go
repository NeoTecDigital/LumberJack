package types

type ProcessInfo struct {
	ID        string `json:"id"`
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	ServerURL string `json:"server_url"`
	// BindHost is the address the API server LISTENS on, and is deliberately separate from
	// ServerURL, which is the address callers are told to reach it at and which the settings route
	// lets a session change. An empty value is not "every interface": internal.ListenAddr reads it
	// as loopback. Binding anywhere else is an explicit act — see `lumberjack serve --host`.
	BindHost      string `json:"bind_host,omitempty"`
	ServerPort    string `json:"server_port"`
	DashboardPort string `json:"dashboard_port"`
	DashboardURL  string `json:"dashboard_url,omitempty"`
	DashboardUp   bool   `json:"dashboard_up"`
	LogPath       string `json:"log_path"`
	DatabasePath  string `json:"database_path"`
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
