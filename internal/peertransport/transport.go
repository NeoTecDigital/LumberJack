package peertransport

import (
	"io"
	"sync"

	"github.com/hashicorp/raft"
)

type Transport struct {
	network *raft.NetworkTransport
	layer   *stream
	guarded *guard
	once    sync.Once
}

func Open(c Config) (*Transport, error) {
	frozen, err := prepare(c)
	if err != nil {
		return nil, err
	}
	layer, err := newStream(frozen)
	if err != nil {
		return nil, err
	}
	network := raft.NewNetworkTransport(layer, frozen.MaxPool, frozen.Timeout, io.Discard)
	t := &Transport{network: network, layer: layer}
	t.guarded = &guard{Transport: network, owner: t, peers: frozen.Peers, local: frozen.LocalID}
	return t, nil
}
func (t *Transport) Raft() raft.Transport { return t.guarded }
func (t *Transport) Close() error {
	t.once.Do(func() { t.network.Close(); t.layer.Close() })
	return nil
}

type guard struct {
	raft.Transport
	owner *Transport
	peers map[raft.ServerID]Peer
	local raft.ServerID
}

func (g *guard) allowed(id raft.ServerID, address raft.ServerAddress) error {
	peer, ok := g.peers[id]
	if !ok || id == g.local || peer.Address != address {
		return ErrPeer
	}
	return nil
}
func (g *guard) Close() error { return g.owner.Close() }
func (g *guard) AppendEntriesPipeline(id raft.ServerID, a raft.ServerAddress) (raft.AppendPipeline, error) {
	if err := g.allowed(id, a); err != nil {
		return nil, err
	}
	return g.Transport.AppendEntriesPipeline(id, a)
}
func (g *guard) AppendEntries(id raft.ServerID, a raft.ServerAddress, req *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) error {
	if err := g.allowed(id, a); err != nil {
		return err
	}
	return g.Transport.AppendEntries(id, a, req, resp)
}
func (g *guard) RequestVote(id raft.ServerID, a raft.ServerAddress, req *raft.RequestVoteRequest, resp *raft.RequestVoteResponse) error {
	if err := g.allowed(id, a); err != nil {
		return err
	}
	return g.Transport.RequestVote(id, a, req, resp)
}
func (g *guard) RequestPreVote(id raft.ServerID, a raft.ServerAddress, req *raft.RequestPreVoteRequest, resp *raft.RequestPreVoteResponse) error {
	if err := g.allowed(id, a); err != nil {
		return err
	}
	return g.owner.network.RequestPreVote(id, a, req, resp)
}
func (g *guard) InstallSnapshot(id raft.ServerID, a raft.ServerAddress, req *raft.InstallSnapshotRequest, resp *raft.InstallSnapshotResponse, data io.Reader) error {
	if err := g.allowed(id, a); err != nil {
		return err
	}
	return g.Transport.InstallSnapshot(id, a, req, resp, data)
}
func (g *guard) TimeoutNow(id raft.ServerID, a raft.ServerAddress, req *raft.TimeoutNowRequest, resp *raft.TimeoutNowResponse) error {
	if err := g.allowed(id, a); err != nil {
		return err
	}
	return g.Transport.TimeoutNow(id, a, req, resp)
}

var _ raft.StreamLayer = (*stream)(nil)
var _ raft.Transport = (*guard)(nil)
var _ raft.WithClose = (*guard)(nil)
var _ raft.WithPreVote = (*guard)(nil)
