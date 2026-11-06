package businessruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/admission"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"github.com/NeoTecDigital/LumberJack/internal/replication"
	"github.com/hashicorp/raft"
	"sync"
	"testing"
	"time"
)

type fixtureAuthority struct {
	authorization Authorization
	denyRead      bool
}

func (a *fixtureAuthority) Resolve(context.Context, Request) (Authorization, error) {
	return a.authorization, nil
}
func (a *fixtureAuthority) AuthorizeRead(context.Context, Access) error {
	if a.denyRead {
		return ErrDenied
	}
	return nil
}
func (a *fixtureAuthority) AuthorizeFence(context.Context, FenceRequest) error { return nil }
func fixtureRuntime(t *testing.T, a CurrentAuthority, v *admission.Verifier) *Runtime {
	t.Helper()
	transports := []*raft.InmemTransport{}
	voters := []raft.Server{}
	for _, id := range []string{"a", "b", "c"} {
		address, tr := raft.NewInmemTransport(raft.ServerAddress(id))
		transports = append(transports, tr)
		voters = append(voters, raft.Server{ID: raft.ServerID(id), Address: address, Suffrage: raft.Voter})
	}
	for _, tr := range transports {
		for _, peer := range transports {
			tr.Connect(peer.LocalAddr(), peer)
		}
	}
	nodes := []*Runtime{}
	for i, voter := range voters {
		r, e := Open(Config{Replication: replication.Config{NodeID: voter.ID, Transport: transports[i], Voters: voters, Bootstrap: i == 0, Directory: t.TempDir(), StorageKey: make([]byte, 32), Timeout: 2 * time.Second}, Verifier: v, Authority: a, Now: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		nodes = append(nodes, r)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			n.Close()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if _, _, e := n.node.Receipt(context.Background(), replication.Scope{AccountID: "account", Product: "momentum"}, "probe"); e == nil {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("leader unavailable")
	return nil
}
func fixtureAdmission(t *testing.T) (*fixtureAuthority, *admission.Verifier, Request, []byte, []byte) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := admission.New(map[string]ed25519.PublicKey{"key": public}, "issuer", "audience", 300)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte(`{"version":1,"algorithm":"AES-256-GCM","keyId":"content","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	digest := sha256.Sum256(payload)
	request := Request{Actor: Actor{"principal", "session"}, Scope: replication.Scope{AccountID: "account", Product: "momentum"}, ResourceID: "resource", RecordID: "record", CommandID: "command", Operation: "create"}
	claims := admission.Claims{Version: 1, Issuer: "issuer", Audience: "audience", PrincipalID: "principal", SessionID: "session", Scope: admission.Scope{AccountID: "account", Product: "momentum"}, GrantRevision: "1", ResourceRevision: "0", ResourceID: "resource", Operation: "create", CommandID: "command", BodySHA256: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Minute).Unix(), BarrierVersion: 1}
	raw, _ := json.Marshal(claims)
	var value map[string]any
	json.Unmarshal(raw, &value)
	canonical, _ := json.Marshal(value)
	proof, _ := json.Marshal(admission.Envelope{KeyID: "key", Payload: base64.RawURLEncoding.EncodeToString(canonical), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonical))})
	authority := &fixtureAuthority{authorization: Authorization{Claims: claims, Context: ciphertext.Context{Version: 1, AccountID: "account", Product: "momentum", ResourceID: "resource", RecordID: "record", Revision: 1, KeyID: "content", Kind: "body"}}}
	return authority, verifier, request, proof, payload
}
func TestCiphertextCommitReadDenialAndDigestMismatch(t *testing.T) {
	a, v, in, proof, payload := fixtureAdmission(t)
	r := fixtureRuntime(t, a, v)
	ctx := context.Background()
	f := FenceRequest{"generation", in.Scope, "principal", "session", 1}
	if e := r.Fence(ctx, f); e != nil {
		t.Fatal(e)
	}
	result, e := r.Commit(ctx, in, proof, payload)
	if e != nil || result.Outcome != "committed" {
		t.Fatalf("commit %+v %v", result, e)
	}
	a.denyRead = true
	if _, _, e = r.Read(ctx, Access{Actor: in.Actor, Scope: in.Scope, ResourceID: in.ResourceID, RecordID: in.RecordID}); e == nil {
		t.Fatal("unauthorized read")
	}
	if _, _, e = r.Receipt(ctx, Access{Actor: in.Actor, Scope: in.Scope, ResourceID: in.ResourceID, CommandID: in.CommandID}); e == nil {
		t.Fatal("unauthorized receipt")
	}
	a.denyRead = false
	changed := append([]byte(nil), payload...)
	changed = append(changed, ' ')
	if _, e = r.Commit(ctx, in, proof, changed); e == nil {
		t.Fatal("changed exact payload digest accepted")
	}
}
func TestConcurrentFenceSerializesAndBlocksOldAdmission(t *testing.T) {
	a, v, in, proof, payload := fixtureAdmission(t)
	r := fixtureRuntime(t, a, v)
	ctx := context.Background()
	f := FenceRequest{"generation", in.Scope, "principal", "session", 2}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Fence(ctx, f) }()
	}
	wg.Wait()
	if e := r.Fence(ctx, f); e != nil {
		t.Fatal(e)
	}
	b, e := r.readBarrier(ctx, in.Scope, "principal", "session")
	if e != nil || !b.Confirmed || b.Version != 2 {
		t.Fatalf("barrier %+v %v", b, e)
	}
	if _, e = r.Commit(ctx, in, proof, payload); e == nil {
		t.Fatal("stale admission committed")
	}
}
func TestMissingAuthorityFailsClosed(t *testing.T) {
	if _, e := Open(Config{}); e == nil {
		t.Fatal("missing authority accepted")
	}
}
