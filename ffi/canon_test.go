// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The Go canon reader over the SPEC.md §11.4 corpus. The corpus is the parent repository's and
// it is the oracle: every frozen hex reproduced, every refusal raised by name at its locus,
// every pair held — or the case is named and the test fails. LJ_CANON_CORPUS points at the
// file and makes it mandatory; without it the parent checkout's path is tried and a missing
// file is a skip. `make canon-check` sets it, so there the gate cannot skip.
package main

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/ffi/canon"
)

const defaultCorpusPath = "../../../crates/intercessor/tests/corpus/canon_corpus.json"

func TestCanonCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	if corpus.MaxDepth != canon.MaxDepth {
		t.Fatalf("corpus max_depth %d, the reader's is %d", corpus.MaxDepth, canon.MaxDepth)
	}
	byName, err := corpus.ByName()
	if err != nil {
		t.Fatal(err)
	}
	var tally corpusTally
	for _, c := range corpus.Cases {
		tally.count(c)
		if err := canon.CheckCase(c); err != nil {
			t.Errorf("case %s: %v", c.Name, err)
		}
	}
	for _, p := range corpus.Pairs {
		if err := canon.CheckPair(p, byName); err != nil {
			t.Errorf("pair %s/%s: %v", p.A, p.B, err)
		}
	}
	t.Logf("canon corpus: %d cases (%d accepted, %d refused, %d id_only; %d ids, %d self-refs) and %d pairs",
		len(corpus.Cases), tally.accepted, tally.refused, tally.idOnly, tally.ids, tally.selfRefs, len(corpus.Pairs))
}

func loadCorpus(t *testing.T) *canon.Corpus {
	t.Helper()
	path, required := os.LookupEnv("LJ_CANON_CORPUS")
	if !required {
		path = defaultCorpusPath
	}
	corpus, err := canon.Load(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		t.Skipf("no corpus at %s and LJ_CANON_CORPUS is unset", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

type corpusTally struct{ accepted, refused, idOnly, ids, selfRefs int }

func (c *corpusTally) count(cs canon.Case) {
	switch cs.Expect {
	case "accepted":
		c.accepted++
	case "refused":
		c.refused++
	case "id_only":
		c.idOnly++
	}
	if cs.IDHex != "" {
		c.ids++
	}
	if cs.SelfRef != "" {
		c.selfRefs++
	}
}
