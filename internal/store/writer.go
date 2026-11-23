// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeoTecDigital/LumberJack/extension"
)

type reply struct {
	r       Receipt
	err     error
	outcome extension.OutcomeState
}
type request struct {
	issuer, digest string
	c              Command
	result         chan reply
}
type candidate struct {
	q      *request
	answer reply
	ops    changes
	body   []byte
}

func (s *Store) Apply(issuer string, raw []byte, permit extension.Permit) (Receipt, error) {
	answer := s.submit(issuer, raw)
	if permit != nil {
		o := extension.Outcome{State: answer.outcome, Err: answer.err}
		switch o.State {
		case extension.WriteDurable:
			o.Commit = extension.Commit{Tiered: true, Seq: answer.r.Sequence, Path: s.path}
		case extension.WriteRefused:
			o.Unchanged = permit.WantsRevision()
		}
		permit.Settle(o)
	}
	return answer.r, answer.err
}
func (s *Store) submit(issuer string, raw []byte) reply {
	s.life.RLock()
	defer s.life.RUnlock()
	s.mu.RLock()
	fenced := s.fault != nil
	s.mu.RUnlock()
	if s.closed || fenced {
		return reply{err: ErrUnavailable, outcome: extension.WriteUnknown}
	}
	if issuer != s.m.Owner {
		return reply{err: ErrDenied}
	}
	c, digest, err := parseCommand(raw, s.m.ReceiptKey)
	if err != nil {
		return reply{err: err}
	}
	q := &request{issuer, digest, c, make(chan reply, 1)}
	s.queue <- q
	return <-q.result
}
func (s *Store) writer() {
	defer close(s.done)
	for first := range s.queue {
		batch := []*request{first}
	drain:
		for len(batch) < 32 {
			select {
			case q, ok := <-s.queue:
				if !ok {
					break drain
				}
				batch = append(batch, q)
			default:
				break drain
			}
		}
		s.commit(batch)
	}
}
func (s *Store) prepare(q *request) candidate {
	c := candidate{q: q}
	if s.fault != nil {
		c.answer = reply{err: ErrUnavailable, outcome: extension.WriteUnknown}
		return c
	}
	if old, ok := s.s.receipts[receiptKey{q.issuer, q.c.ID}]; ok {
		if old.digest == q.digest {
			c.answer = reply{r: old.result, outcome: extension.WriteDurable}
		} else {
			c.answer.err = ErrConflict
		}
		return c
	}
	f, err := s.s.frame(s.m.Store, q.issuer, q.digest, q.c)
	if err == nil {
		c.body, err = json.Marshal(f)
		if err == nil {
			c.body, err = s.key.frame(true, f.Sequence, c.body)
		}
	}
	if err == nil {
		c.ops, c.answer.r, err = s.s.run(f)
	}
	if err != nil {
		c.body = nil
		c.answer.err = err
	}
	return c
}

// Temporarily validate successive drafts under the resident hold; undo the tiny
// before-images before releasing it. Readers see only the last published batch.
func (s *Store) commit(batch []*request) {
	s.mu.Lock()
	s.leases.expire(time.Now())
	cs := make([]candidate, 0, len(batch))
	var last uint64
	for _, q := range batch {
		c := s.prepare(q)
		if len(c.body) > 0 {
			last = s.log.Stage(c.body)
		}
		cs = append(cs, c)
	}
	for i := len(cs) - 1; i >= 0; i-- {
		cs[i].ops.reverse()
	}
	s.mu.Unlock()
	if last != 0 {
		if err := s.log.Commit(last); err != nil {
			s.reconcile(cs, err)
			return
		}
	}
	s.mu.Lock()
	for _, c := range cs {
		c.ops.publish()
	}
	s.mu.Unlock()
	for _, c := range cs {
		if c.answer.err == nil {
			c.answer.outcome = extension.WriteDurable
		}
		c.q.result <- c.answer
	}
}

// Never call Close on the failed writer: it retries the queued suffix. Recover the
// bytes that actually landed, sync them, then settle each permit from its receipt.
func (s *Store) reconcile(cs []candidate, cause error) {
	s.mu.Lock()
	s.fault = ErrUnavailable
	covered := s.s.sequence
	s.mu.Unlock()
	s.log.Abandon()
	log, rs, err := openLog(s.path, covered)
	s.mu.Lock()
	if err == nil {
		err = s.replay(rs)
		if err == nil {
			s.log = log
			s.fault = nil
		} else {
			log.Abandon()
		}
	}
	for i, c := range cs {
		if c.answer.err != nil {
			continue
		}
		switch {
		case err != nil:
			cs[i].answer = reply{err: errors.Join(ErrUnavailable, err), outcome: extension.WriteUnknown}
		default:
			old, ok := s.s.receipts[receiptKey{c.q.issuer, c.q.c.ID}]
			if ok && old.digest == c.q.digest {
				cs[i].answer = reply{r: old.result, outcome: extension.WriteDurable}
			} else {
				cs[i].answer = reply{err: fmt.Errorf("record not committed: %w", cause), outcome: extension.WriteRefused}
			}
		}
	}
	s.mu.Unlock()
	for _, c := range cs {
		c.q.result <- c.answer
	}
}
