package dashboard

import (
	"net/http"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

type DashboardServer struct {
	apiEndpoint string
	server      *http.Server
	logger      types.Logger
}

type TreeNode struct {
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Type     string               `json:"type"`
	Children map[string]*TreeNode `json:"children"`
	Events   map[string]EventData `json:"events"`
	Entries  []EntryData          `json:"entries"`
}

type EventData struct {
	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
	Status    string     `json:"status"`
	Category  string     `json:"category"`
}

type EntryData struct {
	Content   interface{} `json:"content"`
	UserID    string      `json:"user_id"`
	Timestamp time.Time   `json:"timestamp"`
}

type UserData struct {
	ID          string       `json:"id"`
	Username    string       `json:"username"`
	Email       string       `json:"email"`
	Permissions []Permission `json:"permissions"`
}

type Permission int
