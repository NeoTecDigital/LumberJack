// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/extension"
)

func TestProcessExitAfterAppendBeforeSync(t *testing.T) {
	if dir := os.Getenv("LJ_RECORD_CRASH_FIXTURE"); dir != "" {
		// A process exits after the physical append; it sends no receipt and performs
		// neither fsync nor Close. The final, torn frame must not enter the store.
		file, e := os.OpenFile(filepath.Join(dir, "live.dat.log.00000000000000000001"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		bytes, e := os.ReadFile(filepath.Join(dir, "prepared"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write(bytes[:len(bytes)-9]); e != nil {
			t.Fatal(e)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "live.dat")
	s, e := Open(p, "operator")
	if e != nil {
		t.Fatal(e)
	}
	r := must(t, s, create)
	must(t, s, `{"command_id":"torn","edits":[{"op":"create","kind":"item"}]}`)
	log := s.log.Segments()[0]
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(log, filepath.Join(dir, "prepared")); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessExitAfterAppendBeforeSync$")
	cmd.Env = append(os.Environ(), "LJ_RECORD_CRASH_FIXTURE="+dir)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("crash fixture: %s: %v", out, e)
	}
	s, e = Open(p, "operator")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again := must(t, s, create)
	if again.Created[0] != r.Created[0] || s.s.sequence != 1 || len(s.s.receipts) != 1 {
		t.Fatal("recovery did not retain exactly the complete prefix")
	}
}

type partialFailure struct {
	journal
	held             [][]byte
	started, release chan struct{}
	base             uint64
}

func (j *partialFailure) Stage(b []byte) uint64 {
	j.held = append(j.held, b)
	return j.base + uint64(len(j.held))
}
func (j *partialFailure) Commit(_ uint64) error {
	// First call holds the writer, allowing the next two real callers to queue.
	if j.started != nil {
		close(j.started)
		<-j.release
		j.started = nil
		return j.journal.Commit(j.journal.Stage(j.held[0]))
	}
	if len(j.held) != 3 {
		return fmt.Errorf("fixture expected three queued frames, got %d", len(j.held))
	}
	if e := j.journal.Commit(j.journal.Stage(j.held[1])); e != nil {
		return e
	}
	return errors.New("last frame not durable")
}

type settled struct{ out chan extension.Outcome }

func (p settled) WantsRevision() bool        { return false }
func (p settled) Settle(o extension.Outcome) { p.out <- o }
func TestGroupSettlesPermitsByRecoveredPrefix(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	s.log = &partialFailure{journal: s.log, started: entered, release: release}
	// Enqueue the two companions explicitly while the first sync is held, then
	// settle through the same apply completion used by callers.
	first := make(chan error, 1)
	go func() { _, e := s.Apply("operator", []byte(create), nil); first <- e }()
	<-entered
	var wg sync.WaitGroup
	p := settled{make(chan extension.Outcome, 2)}
	for _, k := range []string{"two", "three"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw := fmt.Sprintf(`{"command_id":%q,"edits":[{"op":"create","kind":"v"}]}`, k)
			s.Apply("operator", []byte(raw), p)
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(s.queue) != 2 {
		if time.Now().After(deadline) {
			close(release)
			wg.Wait()
			t.Fatal("companions did not queue")
		}
		runtime.Gosched()
	}
	close(release)
	wg.Wait()
	if e := <-first; e != nil {
		t.Fatal(e)
	}
	a, b := <-p.out, <-p.out
	states := map[extension.OutcomeState]int{}
	states[a.State]++
	states[b.State]++
	if states[extension.WriteDurable] != 1 || states[extension.WriteRefused] != 1 || s.s.sequence != 2 {
		t.Fatalf("outcomes %+v %+v sequence %d", a, b, s.s.sequence)
	}
}
func TestRejectGapMissingBaseOrMissingPrefix(t *testing.T) {
	for _, which := range []string{"gap", "base", "prefix", "prefix-count"} {
		t.Run(which, func(t *testing.T) {
			s, p := openTest(t)
			f := frame{Version: 1, Sequence: 1, Store: s.m.Store, Issuer: "operator", CommandID: "bad", Digest: strings.Repeat("0", 64)}
			prefix := 0
			id := Root
			if which == "gap" {
				f.Sequence++
			}
			if which == "base" {
				id = "absent"
			}
			if which == "prefix-count" {
				prefix = 2
			}
			v := uint64(0)
			f.Expected = map[string]Expected{id: {Revision: &v}}
			e := framedEdit{Edit: Edit{Op: "append", ID: id, Value: json.RawMessage("42")}, Prefix: &prefix}
			if which == "prefix" {
				e.Prefix = nil
			}
			f.Edits = []framedEdit{e}
			raw, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.log.Commit(s.log.Stage(raw)); err != nil {
				t.Fatal(err)
			}
			s.Close()
			h, err := Open(p, "operator")
			if err == nil {
				h.Close()
				t.Fatal("bad frame accepted")
			}
		})
	}
}
