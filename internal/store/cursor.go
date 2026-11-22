// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Access only under the store lock. Continuations are opaque capabilities to
// locate a page, never grants. Fixed expiry is not extended by paging or retries.
const cursorLimit = 32

type cursor struct {
	root         *branch
	seq, access  uint64
	issuer, last string
	plan         scanPlan
	expires      time.Time
}
type cursorCache struct {
	slots [cursorLimit]cursorSlot
	next  int
}
type cursorSlot struct {
	key string
	c   cursor
}

func (cc *cursorCache) get(key, issuer string) (cursor, error) {
	for _, v := range cc.slots {
		if v.key == key && v.c.issuer == issuer && time.Now().Before(v.c.expires) {
			return v.c, nil
		}
	}
	return cursor{}, ErrConflict
}
func (cc *cursorCache) put(c cursor) (string, error) {
	var raw [24]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	key := hex.EncodeToString(raw[:])
	cc.slots[cc.next] = cursorSlot{key, c}
	cc.next = (cc.next + 1) % len(cc.slots)
	return key, nil
}

// Release stale generations as commits progress even if no caller reuses a cursor.
func (cc *cursorCache) expire(now time.Time) {
	for i, v := range cc.slots {
		if v.key != "" && !now.Before(v.c.expires) {
			cc.slots[i] = cursorSlot{}
		}
	}
}
