//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package keyring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKVMQualificationPreparationMatrix(t *testing.T) {
	points := []string{
		"after-previous",
		"after-floor",
		"after-active",
		"after-recovery-abort",
		"after-recovery-active",
	}
	for i, point := range points {
		t.Run(point, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "run")
			plan, err := PrepareKVMQualification(root, int64(100+i), point)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Checkpoint != point || plan.Original.KeyEpoch != 1 || plan.Candidate.KeyEpoch != 2 {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			if plan.Original.EdKeyID == plan.Candidate.EdKeyID || plan.Original.PQKeyID == plan.Candidate.PQKeyID {
				t.Fatal("qualification plan did not rotate both identities")
			}
			for _, path := range []string{plan.Master, plan.Vault, stagedPath(plan.Vault), floorPath(plan.Vault)} {
				info, statErr := os.Lstat(path)
				if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("required durable state invalid: %s info=%v err=%v", path, info, statErr)
				}
			}
			_, prevErr := os.Lstat(previousPath(plan.Vault))
			wantPrevious := point == "after-recovery-abort" || point == "after-recovery-active"
			if wantPrevious && prevErr != nil {
				t.Fatalf("recovery precondition missing previous snapshot: %v", prevErr)
			}
			if !wantPrevious && !os.IsNotExist(prevErr) {
				t.Fatalf("activation plan unexpectedly has previous snapshot: %v", prevErr)
			}
			floor, floorErr := readFloor(plan.Vault)
			if floorErr != nil {
				t.Fatal(floorErr)
			}
			wantFloor := uint64(1)
			if point == "after-recovery-active" {
				wantFloor = 2
			}
			if floor != wantFloor {
				t.Fatalf("wrong prepared floor: got=%d want=%d", floor, wantFloor)
			}
		})
	}
}

func TestKVMQualificationPreparationRejectsUnsafeReuse(t *testing.T) {
	base := t.TempDir()
	if _, err := PrepareKVMQualification(filepath.Join(base, "bad"), 1, "not-a-point"); err == nil {
		t.Fatal("unsupported checkpoint accepted")
	}
	root := filepath.Join(base, "existing")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareKVMQualification(root, 1, "after-previous"); err == nil {
		t.Fatal("existing state directory reused")
	}
}
