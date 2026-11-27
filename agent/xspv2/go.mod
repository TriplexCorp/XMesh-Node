module github.com/TriplexCorp/XMesh-Node/agent/xspv2

go 1.27.3

require (
	github.com/TriplexCorp/XMesh-Node/experiments/quota-v2-retirement-attestation v0.0.0
	github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go v0.0.0
)

replace github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go => ../../security/xspv2/poc-go

replace github.com/TriplexCorp/XMesh-Node/experiments/quota-v2-retirement-attestation => ../../experiments/quota-v2-retirement-attestation
