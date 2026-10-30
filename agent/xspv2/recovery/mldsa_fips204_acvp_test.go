package recovery

import (
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type acvpMLDSASigVerPrompt struct {
	VSID       int                  `json:"vsId"`
	Algorithm  string               `json:"algorithm"`
	Mode       string               `json:"mode"`
	Revision   string               `json:"revision"`
	TestGroups []acvpMLDSATestGroup `json:"testGroups"`
}

type acvpMLDSATestGroup struct {
	TGID               int                 `json:"tgId"`
	TestType           string              `json:"testType"`
	ParameterSet       string              `json:"parameterSet"`
	SignatureInterface string              `json:"signatureInterface"`
	PreHash            string              `json:"preHash"`
	ExternalMu         bool                `json:"externalMu"`
	Tests              []acvpMLDSATestCase `json:"tests"`
}

type acvpMLDSATestCase struct {
	TCID      int    `json:"tcId"`
	PublicKey string `json:"pk"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type acvpMLDSASigVerExpected struct {
	VSID       int                          `json:"vsId"`
	Algorithm  string                       `json:"algorithm"`
	Mode       string                       `json:"mode"`
	Revision   string                       `json:"revision"`
	TestGroups []acvpMLDSAExpectedTestGroup `json:"testGroups"`
}

type acvpMLDSAExpectedTestGroup struct {
	TGID  int                     `json:"tgId"`
	Tests []acvpMLDSAExpectedCase `json:"tests"`
}

type acvpMLDSAExpectedCase struct {
	TCID       int  `json:"tcId"`
	TestPassed bool `json:"testPassed"`
}

func readStrictJSONFile[T any](path string) (T, error) {
	var zero T
	raw, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	var out T
	if err = json.Unmarshal(raw, &out); err != nil {
		return zero, err
	}
	return out, nil
}

func decodeACVPHex(name, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	return decoded, nil
}

func TestMLDSA65FIPS204NISTACVPSigVer(t *testing.T) {
	vectorDir := os.Getenv("NIST_ACVP_MLDSA_SIGVER_DIR")
	if vectorDir == "" {
		t.Skip("official NIST ACVP vector directory not supplied")
	}

	prompt, err := readStrictJSONFile[acvpMLDSASigVerPrompt](filepath.Join(vectorDir, "prompt.json"))
	if err != nil {
		t.Fatalf("read NIST ACVP prompt: %v", err)
	}
	expected, err := readStrictJSONFile[acvpMLDSASigVerExpected](filepath.Join(vectorDir, "expectedResults.json"))
	if err != nil {
		t.Fatalf("read NIST ACVP expected results: %v", err)
	}
	for name, got := range map[string]struct {
		algorithm string
		mode      string
		revision  string
		vsid      int
	}{
		"prompt":   {prompt.Algorithm, prompt.Mode, prompt.Revision, prompt.VSID},
		"expected": {expected.Algorithm, expected.Mode, expected.Revision, expected.VSID},
	} {
		if got.algorithm != "ML-DSA" || got.mode != "sigVer" || got.revision != "FIPS204" || got.vsid != 42 {
			t.Fatalf("unexpected NIST %s metadata: %+v", name, got)
		}
	}

	expectedByTCID := make(map[int]bool)
	for _, group := range expected.TestGroups {
		for _, test := range group.Tests {
			if _, duplicate := expectedByTCID[test.TCID]; duplicate {
				t.Fatalf("duplicate expected tcId %d", test.TCID)
			}
			expectedByTCID[test.TCID] = test.TestPassed
		}
	}

	selectedGroups := 0
	selectedCases := 0
	validCases := 0
	invalidCases := 0
	for _, group := range prompt.TestGroups {
		// Go 1.27 crypto/mldsa exposes the FIPS 204 pure external interface
		// with optional context. ACVP preHash, externalMu and internal-interface
		// groups are deliberately outside this bounded compatibility gate.
		if group.ParameterSet != "ML-DSA-65" || group.SignatureInterface != "external" ||
			group.PreHash != "pure" || group.ExternalMu {
			continue
		}
		selectedGroups++
		for _, test := range group.Tests {
			want, ok := expectedByTCID[test.TCID]
			if !ok {
				t.Fatalf("tgId %d tcId %d missing expected result", group.TGID, test.TCID)
			}

			publicBytes, err := decodeACVPHex("public key", test.PublicKey)
			if err != nil {
				t.Fatalf("tgId %d tcId %d: %v", group.TGID, test.TCID, err)
			}
			message, err := decodeACVPHex("message", test.Message)
			if err != nil {
				t.Fatalf("tgId %d tcId %d: %v", group.TGID, test.TCID, err)
			}
			context, err := decodeACVPHex("context", test.Context)
			if err != nil {
				t.Fatalf("tgId %d tcId %d: %v", group.TGID, test.TCID, err)
			}
			signature, err := decodeACVPHex("signature", test.Signature)
			if err != nil {
				t.Fatalf("tgId %d tcId %d: %v", group.TGID, test.TCID, err)
			}
			if len(publicBytes) != mldsa.MLDSA65PublicKeySize {
				t.Fatalf("tgId %d tcId %d public key length %d, want %d", group.TGID, test.TCID, len(publicBytes), mldsa.MLDSA65PublicKeySize)
			}

			pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicBytes)
			if err != nil {
				t.Fatalf("tgId %d tcId %d parse public key: %v", group.TGID, test.TCID, err)
			}
			verifyErr := mldsa.Verify(pub, message, signature, &mldsa.Options{Context: string(context)})
			got := verifyErr == nil
			if got != want {
				t.Fatalf("tgId %d tcId %d verification=%v want=%v err=%v", group.TGID, test.TCID, got, want, verifyErr)
			}
			selectedCases++
			if want {
				validCases++
			} else {
				invalidCases++
			}
		}
	}

	if selectedGroups == 0 || selectedCases == 0 || validCases == 0 || invalidCases == 0 {
		t.Fatalf("insufficient compatible NIST ACVP coverage: groups=%d cases=%d valid=%d invalid=%d", selectedGroups, selectedCases, validCases, invalidCases)
	}
	t.Logf("verified NIST ACVP ML-DSA-65 FIPS 204 subset: groups=%d cases=%d valid=%d invalid=%d", selectedGroups, selectedCases, validCases, invalidCases)
}
