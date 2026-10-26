// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"testing"
)

func TestCombinedAdapterDelegatesHistoricalStoreProjectionOnly(t *testing.T) {
	for _, item := range []struct {
		body string
		want bool
	}{
		{`{"contractRevision":"png-native-store/0.1","action":"read","query":{"family":"native.command_receipt"}}`, true},
		{`{"contractRevision":"png-native-store/0.1","action":"read","query":{"family":"business:job"}}`, false},
		{`{"contractRevision":"manifest-native/0.1"}`, false},
	} {
		include, err := (combinedAdapter{}).IncludeRetainedReceipts(engine.DomainInput{Mode: "read", Body: []byte(item.body)})
		if err != nil || include != item.want {
			t.Fatal("combined selector incorrect", include, err)
		}
	}
}
