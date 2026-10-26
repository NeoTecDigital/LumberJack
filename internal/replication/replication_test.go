package replication

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/raft"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type cluster struct {
	nodes      []*Node
	transports []*raft.InmemTransport
	config     []Config
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	c := &cluster{}
	voters := []raft.Server{}
	for _, id := range []string{"a", "b", "c"} {
		address, tr := raft.NewInmemTransport(raft.ServerAddress(id))
		c.transports = append(c.transports, tr)
		voters = append(voters, raft.Server{ID: raft.ServerID(id), Address: address, Suffrage: raft.Voter})
	}
	for _, a := range c.transports {
		for _, b := range c.transports {
			a.Connect(b.LocalAddr(), b)
		}
	}
	for i, v := range voters {
		cfg := Config{NodeID: v.ID, Transport: c.transports[i], Voters: voters, Bootstrap: i == 0, Directory: filepath.Join(t.TempDir(), string(v.ID)), StorageKey: make([]byte, 32), Timeout: time.Second, Gate: func(context.Context, Command, uint64) error { return nil }}
		n, e := Open(cfg)
		if e != nil {
			t.Fatal(e)
		}
		c.nodes = append(c.nodes, n)
		cfg.Bootstrap = false
		c.config = append(c.config, cfg)
	}
	t.Cleanup(func() {
		for _, n := range c.nodes {
			n.Close()
		}
	})
	return c
}
func (c *cluster) leader(t *testing.T) (int, *Node) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for i, n := range c.nodes {
			if n.raft.State() == raft.Leader {
				return i, n
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("leader election timeout")
	return 0, nil
}
func fixtureCommand() Command {
	return Command{Scope: Scope{AccountID: "account", Product: "momentum"}, CommandID: "one", Operation: "create", RecordKey: "record", Payload: json.RawMessage(`{"opaque":"ciphertext"}`), PrincipalID: "principal", SessionID: "session", BarrierVersion: 1}
}
func TestThreeVoterReplayFenceAndPartition(t *testing.T) {
	c := newCluster(t)
	i, n := c.leader(t)
	ctx := context.Background()
	command := fixtureCommand()
	r, e := n.Apply(ctx, command)
	if e != nil || r.Outcome != "committed" || r.Revision != 1 {
		t.Fatalf("commit: %+v %v", r, e)
	}
	r, e = n.Apply(ctx, command)
	if e != nil || !r.Replay {
		t.Fatalf("replay: %+v %v", r, e)
	}
	changed := command
	changed.Payload = json.RawMessage(`{"opaque":"changed"}`)
	r, e = n.Apply(ctx, changed)
	if e != nil || r.Outcome != "command_conflict" {
		t.Fatalf("conflict: %+v %v", r, e)
	}
	if e = n.Fence(ctx, command.Scope, "principal", "session", 2); e != nil {
		t.Fatal(e)
	}
	command.CommandID = "stale"
	command.ExpectedRevision = 1
	r, e = n.Apply(ctx, command)
	if e != nil || r.Outcome != "stale_admission" {
		t.Fatalf("fence: %+v %v", r, e)
	}
	c.transports[i].DisconnectAll()
	for j, tr := range c.transports {
		if j != i {
			tr.Disconnect(c.transports[i].LocalAddr())
		}
	}
	command.CommandID = "minority"
	command.BarrierVersion = 2
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, e = n.Apply(bounded, command)
	if e == nil && r.Outcome == "committed" {
		t.Fatal("minority committed")
	}
}
func TestEncryptedPersistenceAndSnapshotRestart(t *testing.T) {
	c := newCluster(t)
	_, n := c.leader(t)
	command := fixtureCommand()
	ctx := context.Background()
	if _, e := n.Apply(ctx, command); e != nil {
		t.Fatal(e)
	}
	if e := n.raft.Snapshot().Error(); e != nil {
		t.Fatal(e)
	}
	for i, node := range c.nodes {
		if e := node.Close(); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(filepath.Join(c.config[i].Directory, "raft.enc"))
		if e != nil {
			t.Fatal(e)
		}
		if json.Valid(b) {
			t.Fatal("plaintext raft persistence")
		}
	}
	reconnectCluster(c)
	for i, cfg := range c.config {
		node, e := Open(cfg)
		if e != nil {
			t.Fatal(e)
		}
		c.nodes[i] = node
	}
	_, n = c.leader(t)
	r, ok, e := n.Receipt(ctx, command.Scope, command.CommandID)
	if e != nil || !ok || r.Revision != 1 {
		t.Fatalf("restored receipt: %+v %v %v", r, ok, e)
	}
	r, e = n.Apply(ctx, command)
	if e != nil || !r.Replay {
		t.Fatalf("restored replay: %+v %v", r, e)
	}
}

// Raft shutdown disconnects in-memory transports; a restarted process needs fresh connections.
func reconnectCluster(c *cluster) {
	for i, tr := range c.transports {
		_, fresh := raft.NewInmemTransport(tr.LocalAddr())
		c.transports[i] = fresh
		c.config[i].Transport = fresh
	}
	for _, a := range c.transports {
		for _, b := range c.transports {
			a.Connect(b.LocalAddr(), b)
		}
	}
}
