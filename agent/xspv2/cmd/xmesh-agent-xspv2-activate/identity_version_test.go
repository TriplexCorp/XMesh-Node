//go:build linux

package main

import "testing"

func TestActivationProductionVersionValidation(t *testing.T) {
	for _, value := range []string{"control-v6.0.0", "control-v6.0.5", "control-v6.12.3"} {
		if !validProductionVersion(value) {
			t.Fatalf("rejected production version %q", value)
		}
	}
	for _, value := range []string{"strict-pq-unreleased", "control-v5.0.0", "control-v6.00.5", "control-v6.0.05"} {
		if validProductionVersion(value) {
			t.Fatalf("accepted invalid production version %q", value)
		}
	}
}
