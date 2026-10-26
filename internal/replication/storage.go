package replication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/hashicorp/raft"
	"os"
	"path/filepath"
	"sync"
)

type diskState struct {
	Logs   map[uint64]*raft.Log
	Stable map[string][]byte
}
type diskStore struct {
	mu    sync.Mutex
	path  string
	aead  cipher.AEAD
	state diskState
}

func openDisk(dir string, key []byte) (*diskStore, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	d := &diskStore{path: filepath.Join(dir, "raft.enc"), aead: a, state: diskState{make(map[uint64]*raft.Log), make(map[string][]byte)}}
	b, e := os.ReadFile(d.path)
	if os.IsNotExist(e) {
		return d, nil
	}
	if e != nil {
		return nil, e
	}
	b, e = d.decrypt(b, "raft-state-v1")
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(b, &d.state)
	return d, e
}
func (d *diskStore) encrypt(b []byte, aad string) ([]byte, error) {
	n := make([]byte, d.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return d.aead.Seal(n, n, b, []byte(aad)), nil
}
func (d *diskStore) decrypt(b []byte, aad string) ([]byte, error) {
	n := d.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("replication: corrupt encrypted state")
	}
	return d.aead.Open(nil, b[:n], b[n:], []byte(aad))
}
func atomicFile(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".raft-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (d *diskStore) persist() error {
	b, e := json.Marshal(d.state)
	if e != nil {
		return e
	}
	b, e = d.encrypt(b, "raft-state-v1")
	if e != nil {
		return e
	}
	return atomicFile(d.path, b)
}
func (d *diskStore) FirstIndex() (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n uint64
	for k := range d.state.Logs {
		if n == 0 || k < n {
			n = k
		}
	}
	return n, nil
}
func (d *diskStore) LastIndex() (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n uint64
	for k := range d.state.Logs {
		if k > n {
			n = k
		}
	}
	return n, nil
}
func (d *diskStore) GetLog(index uint64, out *raft.Log) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.state.Logs[index]
	if !ok {
		return raft.ErrLogNotFound
	}
	*out = *l
	out.Data = append([]byte(nil), l.Data...)
	out.Extensions = append([]byte(nil), l.Extensions...)
	return nil
}
func (d *diskStore) StoreLog(l *raft.Log) error { return d.StoreLogs([]*raft.Log{l}) }
func (d *diskStore) StoreLogs(logs []*raft.Log) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, l := range logs {
		c := *l
		c.Data = append([]byte(nil), l.Data...)
		c.Extensions = append([]byte(nil), l.Extensions...)
		d.state.Logs[l.Index] = &c
	}
	return d.persist()
}
func (d *diskStore) DeleteRange(min, max uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.state.Logs {
		if k >= min && k <= max {
			delete(d.state.Logs, k)
		}
	}
	return d.persist()
}
func (d *diskStore) Set(key, val []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state.Stable[string(key)] = append([]byte(nil), val...)
	return d.persist()
}
func (d *diskStore) Get(key []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.state.Stable[string(key)]...), nil
}
func (d *diskStore) SetUint64(key []byte, v uint64) error {
	b, _ := json.Marshal(v)
	return d.Set(key, b)
}
func (d *diskStore) GetUint64(key []byte) (uint64, error) {
	b, e := d.Get(key)
	if e != nil || len(b) == 0 {
		return 0, e
	}
	var v uint64
	e = json.Unmarshal(b, &v)
	return v, e
}
