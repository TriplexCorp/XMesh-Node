package main

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// The initial release must understand a signed successor without already
// containing that successor's version. This is a version predicate, not an
// authorization: callers still require the original enrolled identity, exact
// signed plan/outcome, command, deadline and measured artifact.
func forwardReleaseVersion(current, target string) bool {
	parse := func(value string) ([2]uint64, bool) {
		var out [2]uint64
		if !validProductionVersion(value) {
			return out, false
		}
		parts := strings.Split(strings.TrimPrefix(value, "control-v6."), ".")
		for i, part := range parts {
			number, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return out, false
			}
			out[i] = number
		}
		return out, true
	}
	from, fromOK := parse(current)
	to, toOK := parse(target)
	return fromOK && toOK && (to[0] > from[0] || (to[0] == from[0] && to[1] > from[1]))
}

func validForwardProductRelease(current, target releaseIdentity) bool {
	validHex := func(value string, length int) bool {
		if len(value) != length || strings.ToLower(value) != value {
			return false
		}
		_, err := hex.DecodeString(value)
		return err == nil
	}
	return forwardReleaseVersion(current.Version, target.Version) &&
		validHex(current.SourceRevision, 40) && validHex(target.SourceRevision, 40) &&
		validHex(current.ArtifactSHA256, 64) && validHex(target.ArtifactSHA256, 64) &&
		current.SourceRevision != target.SourceRevision && current.ArtifactSHA256 != target.ArtifactSHA256
}
