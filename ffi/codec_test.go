// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The codec's one load-bearing property, which the C smoke cannot see: the wire names are the HTTP
// surface's json names, because every document is routed through JSON rather than tagged twice.
package main

import (
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
)

func TestEncodeUsesJSONFieldNames(t *testing.T) {
	// QueryResponse's json tags are next_cursor / total / results. yaml.v3 over the struct directly
	// would lowercase-mangle them to nextcursor and so on; the codec routes through JSON, so the wire
	// carries the exact names the HTTP surface does.
	doc, err := encodeYAML(embedded.QueryResponse{NextCursor: "abc", Total: 3})
	if err != nil {
		t.Fatalf("encodeYAML: %v", err)
	}
	text := string(doc)

	for _, want := range []string{"next_cursor:", "total:", "results:"} {
		if !strings.Contains(text, want) {
			t.Errorf("wire document is missing %q; got:\n%s", want, text)
		}
	}
	if strings.Contains(text, "nextcursor") {
		t.Errorf("wire document carries the yaml-mangled name nextcursor:\n%s", text)
	}
}

func TestCodecPreservesLargeIntegersAcrossTheWire(t *testing.T) {
	// epoch, oldest and sequence are UnixNano-scale, past 2^53 where float64 begins dropping integers.
	// Round-tripped through the ACTUAL wire — encode then decode — each must come back exact.
	for _, n := range []uint64{1 << 53, (1 << 53) + 1, 1788850115679188055} {
		doc, err := encodeYAML(pollResponse{Epoch: n, Oldest: n})
		if err != nil {
			t.Fatalf("encodeYAML(%d): %v", n, err)
		}

		var back pollResponse
		if err := decodeYAML(doc, &back); err != nil {
			t.Fatalf("decodeYAML(%d): %v\nwire:\n%s", n, err, doc)
		}
		if back.Epoch != n || back.Oldest != n {
			t.Errorf("large integer not preserved: sent %d, got epoch=%d oldest=%d\nwire:\n%s",
				n, back.Epoch, back.Oldest, doc)
		}
	}
}

func TestDecodeReadsJSONFieldNamesIntoTypedFields(t *testing.T) {
	var r embedded.AppendEventRequest
	if err := decodeYAML([]byte("path: work/site\nevent_id: e1\ncontent: hello\n"), &r); err != nil {
		t.Fatalf("decodeYAML: %v", err)
	}
	if r.Path != "work/site" || r.EventID != "e1" || r.Content != "hello" {
		t.Fatalf("decoded the wrong values: %+v", r)
	}
}
