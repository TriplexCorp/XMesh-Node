//go:build linux

package runtime

import "testing"

func TestEndpointValidationSeparatesConnectAddressAndAuthority(t *testing.T) {
	if err := (Endpoint{Address: "10.0.0.8:8444", ServerName: "node-ingress.xsp.invalid"}).Validate(); err != nil {
		t.Fatalf("valid direct address + authenticated authority rejected: %v", err)
	}
	for _, endpoint := range []Endpoint{
		{Address: "https://node.example:8444", ServerName: "node.example"},
		{Address: "node.example:8444/path", ServerName: "node.example"},
		{Address: "node.example", ServerName: "node.example"},
		{Address: "node.example:8444", ServerName: ""},
		{Address: "node.example:8444", ServerName: "node.example:8444"},
	} {
		if err := endpoint.Validate(); err == nil {
			t.Fatalf("invalid endpoint accepted: %+v", endpoint)
		}
	}
}
