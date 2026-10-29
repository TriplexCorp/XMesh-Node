//go:build linux

package main

import "testing"

func TestReleaseVersionValidation(t *testing.T) {
	for _, value := range []string{"p0d2-ci", "agent_1+pq", "A", "control-v5.2.0"} {
		if !validReleaseVersion(value) {
			t.Fatalf("expected valid version %q", value)
		}
	}
	for _, value := range []string{"", "-bad", ".bad", "bad/path", "bad value"} {
		if validReleaseVersion(value) {
			t.Fatalf("expected invalid version %q", value)
		}
	}
}

func TestSourceRevisionRequiresCanonicalLowercaseCommit(t *testing.T) {
	if !validSourceRevision("0123456789abcdef0123456789abcdef01234567") {
		t.Fatal("expected canonical lowercase 40-hex revision")
	}
	for _, value := range []string{
		"",
		"0123456789abcdef0123456789abcdef0123456",
		"0123456789abcdef0123456789abcdef012345678",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"g123456789abcdef0123456789abcdef01234567",
	} {
		if validSourceRevision(value) {
			t.Fatalf("expected invalid revision %q", value)
		}
	}
}

func TestUnpinnedDevelopmentBuildCannotClaimReleaseIdentity(t *testing.T) {
	oldVersion, oldRevision := version, sourceRevision
	t.Cleanup(func() {
		version, sourceRevision = oldVersion, oldRevision
	})
	version = "p0d2-ci"
	sourceRevision = "development"
	if _, err := releaseIdentity(); err == nil {
		t.Fatal("development build must fail closed for --identity")
	}
}

func TestPinnedBuildIdentityIsExact(t *testing.T) {
	oldVersion, oldRevision := version, sourceRevision
	t.Cleanup(func() {
		version, sourceRevision = oldVersion, oldRevision
	})
	version = "p0d2-ci"
	sourceRevision = "0123456789abcdef0123456789abcdef01234567"
	identity, err := releaseIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.Version != version || identity.SourceRevision != sourceRevision {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}
