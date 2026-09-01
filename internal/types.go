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
	forest   *core.Node
	cache    *Cache
	apiQueue *APIQueue
	// forestMutex is the ONE lock over the whole forest. Held exclusively across a mutation and
	// the persist that acknowledges it, shared by everything that reads the graph. See
	// forest_lock.go for why a per-node mutex cannot stand in for it.
	forestMutex sync.RWMutex
	jwtConfig   JWTConfig
	logger      types.Logger
	server      *http.Server
	config      types.ServerConfig
	logCache    *LogCache
	lastHash    []byte
	// mutations is the fan-out behind GET /stream. Published to AFTER a change is persisted and
	// acknowledged, never before: announcing something that has not been written is the same lie
	// as a 200 for it.
	mutations *mutationStream
	// logCloser releases the logger's file sink at shutdown. It is nil when the logger only writes
	// to standard error, which is what an unconfigured log path leaves it doing.
	logCloser io.Closer
}
