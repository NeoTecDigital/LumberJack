// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStagedLegacyFailedAuthorityConfigurationCannotDowngradeFence(t *testing.T) {
	for _, kind := range []string{"domain", "personal", "native"} {
		t.Run(kind, func(t *testing.T) { sourceLegacyFailedConfiguration(t, kind) })
	}
}

func sourceLegacyFailedConfiguration(t *testing.T, kind string) {
	t.Helper()
	server := stagedTestConfigured(t)
	var err error
	switch kind {
	case "domain":
		err = server.ConfigureDomain(DomainConfig{}, nil, nil)
	case "personal":
		_, err = server.ConfigurePersonalSource(PersonalSourceConfig{})
	case "native":
		_, err = server.ConfigureNativeControl(nil)
	}
	if err == nil || server.domain != nil || server.personalSource.Load() != nil || server.nativeControl.Load() != nil {
		t.Fatal("fixture did not retain a failed, uninstalled authority attempt")
	}
	sourceLegacyRequireStrictUnknown(t, server)
}

func sourceLegacyRequireStrictUnknown(t *testing.T, server *Server) {
	t.Helper()
	if !server.sourceFence().required {
		t.Fatal("actual/attempted authority lost its monotonic fence")
	}
	err := server.changeForest(func() error {
		server.forest.Metadata = map[string]interface{}{"outside": "changed but unacknowledged"}
		return errors.New("synthetic callback failure after live mutation")
	})
	if err == nil || !server.sourceFence().unknown || server.forest.Metadata["outside"] == nil {
		t.Fatal("protected authority path discarded unknown/no-rollback semantics")
	}
	called := false
	if err := server.changeForest(func() error { called = true; return nil }); err == nil || called {
		t.Fatal("unknown source outcome admitted an unrelated legacy operation")
	}
}

func TestStagedConfiguredAuthorityFenceDoesNotDependOnCurrentPointer(t *testing.T) {
	domain := domainTestConfigured(t).server
	domain.forestMutex.Lock()
	domain.domain = nil // Simulates teardown; never authorization for a downgrade.
	domain.forestMutex.Unlock()
	sourceLegacyRequireStrictUnknown(t, domain)
	personal := sourceUnitFixtureNew(t).server
	personal.personalSource.Store(nil)
	sourceLegacyRequireStrictUnknown(t, personal)
}

func TestStagedLegacyInFlightTransitionDrainsBeforeSourceEvidence(t *testing.T) {
	c := stagedTestConfigured(t).sourceFence()
	legacy, err := c.beginOrdinaryWrite(context.Background(), "ordinary-in-flight")
	if err != nil || legacy.writer != nil || c.legacyRunning != 1 {
		t.Fatal("legacy compatibility operation was not registered")
	}
	c.requireFencing()
	if _, err := c.beginRead(nil); err == nil {
		t.Fatal("source evidence bypassed an in-flight legacy publication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.beginWrite(ctx, "configure-after-legacy"); err == nil {
		t.Fatal("private source writer bypassed in-flight legacy publication")
	}
	legacy.finish(false, true)
	writer, err := c.beginWrite(context.Background(), "configure-after-legacy")
	if err != nil || c.legacyRunning != 0 {
		t.Fatal("drained compatibility operation stranded source activation")
	}
	writer.finish(true, true)
	ordinary, err := c.beginOrdinaryWrite(context.Background(), "ordinary-after-config")
	if err != nil || ordinary.writer == nil {
		t.Fatal("post-activation legacy write downgraded to compatibility mode")
	}
	ordinary.finish(true, false)
}

func TestStagedLegacyReopenBeforeConfigurePreservesOwnedArtifactGuards(t *testing.T) {
	original := stagedTestConfigured(t)
	reopened := sourceLegacyReopen(t, original)
	if reopened.sourceFence().required {
		t.Fatal("generic legacy staged namespace was treated as configured authority")
	}
	sourceLegacyRequireArtifactProtection(t, reopened)
	if err := reopened.changeForest(func() error { return nil }); err != nil {
		t.Fatal("permitted legacy reconvergence was poisoned")
	}
}

func TestStagedPersistedDomainBeforeConfigureRetainsFenceAndArtifacts(t *testing.T) {
	original := domainTestConfigured(t).server
	reopened := sourceLegacyReopen(t, original)
	if reopened.domain != nil || reopened.personalSource.Load() != nil {
		t.Fatal("reopen fixture unexpectedly configured authority")
	}
	sourceLegacyRequireArtifactProtection(t, reopened)
	sourceLegacyRequireStrictUnknown(t, reopened)
}

func sourceLegacyReopen(t *testing.T, original *Server) *Server {
	t.Helper()
	reopened := stagedTestServer(t, original.config.Process.DatabasePath)
	if err := reopened.loadFromFile(original.statePath()); err != nil {
		t.Fatal(err)
	}
	return reopened
}

func sourceLegacyRequireArtifactProtection(t *testing.T, server *Server) {
	t.Helper()
	record := stagedTestRecord(t, server.forest)
	if err := server.changeForest(func() error { record.Metadata["label"] = "forbidden"; return nil }); err == nil {
		t.Fatal("compatibility permit bypassed persisted owned protection")
	}
	stagedTestRequireLabel(t, record, "original")
	artifact := stagedTestArtifact(t, server, "owned-new-id")
	if err := server.changeForest(func() error { server.forest.Children["artifact"] = artifact; return nil }); err == nil {
		t.Fatal("copied persisted owned artifact escaped protection")
	}
	stagedTestNoLegacyOwnedDisclosure(t, server)
}

func TestStagedPersistedPersonalSourceBeforeConfigureRetainsFence(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	_, raw, actor := sourceUnitAdmitted(t, f)
	if _, err := f.p.executePersonal(context.Background(), sourceUnitRequest(f, "binding.provision", sourcePersonalExecute{raw, actor.ExecutionLease, "unit_legacy_reopen"})); err != nil {
		t.Fatal(err)
	}
	reopened := sourceLegacyReopen(t, f.server)
	if reopened.forest.PersonalBindings == nil || reopened.personalSource.Load() != nil {
		t.Fatal("fixture did not reopen retained private state before configuration")
	}
	sourceLegacyRequireStrictUnknown(t, reopened)
}
