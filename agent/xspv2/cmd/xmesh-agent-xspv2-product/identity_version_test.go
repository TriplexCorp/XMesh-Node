package main

import (
	"strings"
	"testing"
)

func TestIdentityAcceptsCurrentProductionPatch(t *testing.T) {
	oldVersion, oldRevision := version, sourceRevision
	defer func() { version, sourceRevision = oldVersion, oldRevision }()
	version = "control-v6.0.5"
	sourceRevision = strings.Repeat("a", 40)
	got, err := identity()
	if err != nil {
		t.Fatalf("identity rejected current production patch: %v", err)
	}
	if got.Version != version || got.SourceRevision != sourceRevision || len(got.ArtifactSHA256) != 64 {
		t.Fatalf("unexpected identity: %#v", got)
	}
}

func TestProductionVersionRejectsNonReleaseIdentity(t *testing.T) {
	for _, value := range []string{"dev", "strict-pq-unreleased", "control-v5.9.9", "control-v6.00.5", "control-v6.0.05", "control-v6.0"} {
		if validProductionVersion(value) {
			t.Fatalf("accepted non-production version %q", value)
		}
	}
}
