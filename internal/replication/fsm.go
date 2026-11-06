package replication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/hashicorp/raft"
	"io"
	"sync"
)

type savedReceipt struct {
	Digest string
	Result Result
}
type state struct {
	Records  map[recordKey]Record
	Receipts map[recordKey]savedReceipt
	Fences   map[actorKey]uint64
}
type machine struct {
	mu    sync.RWMutex
	state state
}

func newMachine() *machine {
	return &machine{state: state{make(map[recordKey]Record), make(map[recordKey]savedReceipt), make(map[actorKey]uint64)}}
}
func digest(c Command) string {
	c.Admission = nil
	var payload interface{}
	decoder := json.NewDecoder(bytes.NewReader(c.Payload))
	decoder.UseNumber()
	if decoder.Decode(&payload) == nil {
		c.Payload, _ = json.Marshal(payload)
	}
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (m *machine) Apply(l *raft.Log) interface{} {
	var w wire
	if json.Unmarshal(l.Data, &w) != nil {
		return Result{Outcome: "invalid"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if w.Fence != nil {
		f := w.Fence
		k := actorKey{f.Scope.key(), f.Principal, f.Session}
		if f.Version > m.state.Fences[k] {
			m.state.Fences[k] = f.Version
		}
		return Result{Outcome: "fenced", Revision: m.state.Fences[k]}
	}
	if w.Command == nil {
		return Result{Outcome: "invalid"}
	}
	return m.apply(*w.Command)
}
func (m *machine) apply(c Command) Result {
	k := recordKey{c.Scope.key(), c.CommandID}
	d := digest(c)
	if r, ok := m.state.Receipts[k]; ok {
		if r.Digest != d {
			return Result{CommandID: c.CommandID, Outcome: "command_conflict"}
		}
		result := r.Result
		result.Replay = true
		return result
	}
	r := Result{CommandID: c.CommandID, Outcome: "committed"}
	key := recordKey{c.Scope.key(), c.RecordKey}
	prior := m.state.Records[key]
	current := m.state.Fences[actorKey{c.Scope.key(), c.PrincipalID, c.SessionID}]
	if c.BarrierVersion < current {
		r.Outcome = "stale_admission"
	} else if prior.Revision != c.ExpectedRevision {
		r.Outcome = "revision_conflict"
	} else if prior.Revision == ^uint64(0) {
		r.Outcome = "revision_exhausted"
	} else {
		r.Revision = prior.Revision + 1
		m.state.Records[key] = Record{r.Revision, append(json.RawMessage(nil), c.Payload...)}
	}
	m.state.Receipts[k] = savedReceipt{d, r}
	return r
}

// Snapshot encoding uses arrays because structural map keys are not JSON keys.
type recordEntry struct {
	Key   recordKey
	Value Record
}
type receiptEntry struct {
	Key   recordKey
	Value savedReceipt
}
type fenceEntry struct {
	Key   actorKey
	Value uint64
}
type imageState struct {
	Records  []recordEntry
	Receipts []receiptEntry
	Fences   []fenceEntry
}

func (m *machine) Snapshot() (raft.FSMSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := imageState{}
	for k, v := range m.state.Records {
		s.Records = append(s.Records, recordEntry{k, v})
	}
	for k, v := range m.state.Receipts {
		s.Receipts = append(s.Receipts, receiptEntry{k, v})
	}
	for k, v := range m.state.Fences {
		s.Fences = append(s.Fences, fenceEntry{k, v})
	}
	b, e := json.Marshal(s)
	return &snapshot{b}, e
}
func (m *machine) Restore(r io.ReadCloser) error {
	defer r.Close()
	var s imageState
	if e := json.NewDecoder(r).Decode(&s); e != nil {
		return e
	}
	n := newMachine()
	for _, e := range s.Records {
		n.state.Records[e.Key] = e.Value
	}
	for _, e := range s.Receipts {
		n.state.Receipts[e.Key] = e.Value
	}
	for _, e := range s.Fences {
		n.state.Fences[e.Key] = e.Value
	}
	m.mu.Lock()
	m.state = n.state
	m.mu.Unlock()
	return nil
}

type snapshot struct{ data []byte }

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	if _, e := sink.Write(s.data); e != nil {
		sink.Cancel()
		return e
	}
	return sink.Close()
}
func (s *snapshot) Release() {}
