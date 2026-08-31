package internal

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SessionKey []byte
	RefreshKey []byte
	ExpiresIn  time.Duration
	SecretKey  []byte
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Trace     string    `json:"trace,omitempty"`
	Indent    int       `json:"indent"`
	Type      string    `json:"type"`
}

type LogCache struct {
	Logs        []LogEntry
	LastOffset  int64
	LastModTime time.Time
	PageSize    int
	mutex       sync.RWMutex
}

type Cache struct {
	Forest     *core.Node
	LastHash   []byte
	LastUpdate time.Time
	mutex      sync.RWMutex
}

type APIQueue struct {
	queue    chan APIRequest
	workers  int
	wg       sync.WaitGroup
	shutdown chan struct{}
}

type APIRequest struct {
	Type     string
	Path     string
	Callback func(*core.Node) interface{}
	Response chan APIResponse
}

type APIResponse struct {
	Data  interface{}
	Error error
}

type Server struct {
	forest    *core.Node
	cache     *Cache
	apiQueue  *APIQueue
	mutex     sync.Mutex
	jwtConfig JWTConfig
	logger    types.Logger
	server    *http.Server
	config    types.ServerConfig
	logCache  *LogCache
	lastHash  []byte
	// logCloser releases the logger's file sink at shutdown. It is nil when the logger only writes
	// to standard error, which is what an unconfigured log path leaves it doing.
	logCloser io.Closer
}
