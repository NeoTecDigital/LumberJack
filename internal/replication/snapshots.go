package replication

import (
	"bytes"
	"encoding/json"
	"github.com/hashicorp/raft"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type snapshotStore struct {
	disk *diskStore
	dir  string
}
type snapshotFile struct {
	Meta raft.SnapshotMeta
	Data []byte
}
type encryptedSink struct {
	bytes.Buffer
	store    *snapshotStore
	meta     raft.SnapshotMeta
	canceled bool
}

func (s *snapshotStore) Create(v raft.SnapshotVersion, index, term uint64, c raft.Configuration, ci uint64, t raft.Transport) (raft.SnapshotSink, error) {
	id := fmtID(index, term)
	return &encryptedSink{store: s, meta: raft.SnapshotMeta{Version: v, ID: id, Index: index, Term: term, Configuration: c, ConfigurationIndex: ci}}, nil
}
func fmtID(i, t uint64) string {
	b, _ := json.Marshal([]uint64{i, t})
	return string(bytes.ReplaceAll(bytes.Trim(b, "[]"), []byte(","), []byte("-")))
}
func (s *snapshotStore) List() ([]*raft.SnapshotMeta, error) {
	files, e := filepath.Glob(filepath.Join(s.dir, "snapshot-*.enc"))
	if e != nil {
		return nil, e
	}
	result := []*raft.SnapshotMeta{}
	for _, f := range files {
		v, e := s.load(filepath.Base(f))
		if e != nil {
			return nil, e
		}
		m := v.Meta
		result = append(result, &m)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index > result[j].Index })
	return result, nil
}
func (s *snapshotStore) load(name string) (snapshotFile, error) {
	var v snapshotFile
	b, e := os.ReadFile(filepath.Join(s.dir, name))
	if e != nil {
		return v, e
	}
	b, e = s.disk.decrypt(b, name)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func (s *snapshotStore) Open(id string) (*raft.SnapshotMeta, io.ReadCloser, error) {
	if filepath.Base(id) != id {
		return nil, nil, ErrInvalid
	}
	v, e := s.load("snapshot-" + id + ".enc")
	if e != nil {
		return nil, nil, e
	}
	return &v.Meta, io.NopCloser(bytes.NewReader(v.Data)), nil
}
func (s *encryptedSink) ID() string    { return s.meta.ID }
func (s *encryptedSink) Cancel() error { s.canceled = true; s.Reset(); return nil }
func (s *encryptedSink) Close() error {
	if s.canceled {
		return ErrInvalid
	}
	s.meta.Size = int64(s.Len())
	b, e := json.Marshal(snapshotFile{s.meta, s.Bytes()})
	if e != nil {
		return e
	}
	name := "snapshot-" + s.meta.ID + ".enc"
	b, e = s.store.disk.encrypt(b, name)
	if e != nil {
		return e
	}
	return atomicFile(filepath.Join(s.store.dir, name), b)
}
