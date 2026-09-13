package scope

import "testing"

func TestScopePolicy(t *testing.T) {
	policy := &Policy{
		Allow: []string{"192.168.1.0/24", "*.example.com", "127.0.0.1"},
		Deny:  []string{"192.168.1.50", "prod.example.com"},
	}
	if err := policy.Compile(); err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	if !policy.IsAllowed("192.168.1.20") {
		t.Errorf("expected 192.168.1.20 to be allowed")
	}
	if policy.IsAllowed("192.168.1.50") {
		t.Errorf("expected 192.168.1.50 to be denied")
	}
	if !policy.IsAllowed("api.example.com") {
		t.Errorf("expected api.example.com to be allowed")
	}
	if policy.IsAllowed("prod.example.com") {
		t.Errorf("expected prod.example.com to be denied")
	}
	if policy.IsAllowed("8.8.8.8") {
		t.Errorf("expected 8.8.8.8 to be denied (not in allow list)")
	}
}
